#include "mcp/server.hpp"
#include "common.hpp"
#include <iostream>

namespace ida_mcp::mcp {
    McpServer::McpServer() {
        // Set server capabilities (MCP 2025-11-25)
        capabilities_ = json{
            {"tools", json::object()},
            {"resources", json::object()},
            {"prompts", json::object()},
            {"logging", json::object()}  // Support logging API
        };
    }

    McpServer::~McpServer() = default;

    void McpServer::register_tool(const ToolDefinition &def, ToolHandler handler) {
        std::lock_guard<std::mutex> lock(mutex_);
        tools_[def.name] = ToolEntry{def, std::move(handler)};
    }

    std::vector<ToolDefinition> McpServer::get_tools() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ToolDefinition> result;
        result.reserve(tools_.size());
        for (const auto &[name, entry]: tools_) {
            result.push_back(entry.definition);
        }
        return result;
    }

    McpResponse McpServer::handle_request(const McpRequest &request) {
        // Handle notifications (no id) - including cancellation
        if (!request.id.has_value()) {
            // Process notification handlers
            if (request.method == "notifications/cancelled") {
                handle_cancelled(request.params);
            }
            return McpResponse::notification_accepted();
        }

        json request_id = request.id.value();

        // Check if this request was cancelled - silently drop per MCP spec
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (cancelled_requests_.count(request_id) > 0) {
                cancelled_requests_.erase(request_id);
                // MCP spec: cancelled requests should be silently dropped
                return McpResponse::notification_accepted();
            }
        }

        try {
            json result;

            // Core methods
            if (request.method == "initialize") {
                result = handle_initialize(request.params);
            } else if (request.method == "ping") {
                result = handle_ping(request.params);
            }
            // Tools API
            else if (request.method == "tools/list") {
                result = handle_tools_list(request.params);
            } else if (request.method == "tools/call") {
                result = handle_tools_call(request.params);
            }
            // Resources API (MCP 2025-11-25)
            else if (request.method == "resources/list") {
                result = handle_resources_list(request.params);
            } else if (request.method == "resources/read") {
                result = handle_resources_read(request.params);
            } else if (request.method == "resources/templates/list") {
                result = handle_resource_templates_list(request.params);
            }
            // Prompts API (MCP 2025-11-25)
            else if (request.method == "prompts/list") {
                result = handle_prompts_list(request.params);
            } else if (request.method == "prompts/get") {
                result = handle_prompts_get(request.params);
            }
            // Logging API (MCP 2025-11-25)
            else if (request.method == "logging/setLevel") {
                result = handle_logging_set_level(request.params);
            }
            // Unknown method
            else {
                return McpResponse::make_error(request_id, error_codes::METHOD_NOT_FOUND,
                                               "Method not found: " + request.method);
            }

            return McpResponse::success(request_id, std::move(result));
        } catch (const std::exception &e) {
            return McpResponse::make_error(request_id, error_codes::INTERNAL_ERROR, e.what());
        }
    }

    json McpServer::handle_initialize(const json &params) {
        return json{
            {"protocolVersion", "2025-11-25"},
            {"capabilities", capabilities_},
            {
                "serverInfo", {
                    {"name", "ida-mcp-server"},
                    {"version", "1.0.0"}
                }
            }
        };
    }

    json McpServer::handle_tools_list(const json &params) {
        std::lock_guard<std::mutex> lock(mutex_);

        json tools_array = json::array();
        for (const auto &[name, entry]: tools_) {
            tools_array.push_back(entry.definition.to_json());
        }

        json result = {{"tools", tools_array}};

        // Pagination support - cursor in params, nextCursor in result
        // For now, we return all tools (no pagination needed for small sets)
        // If params contains "cursor", we would resume from that position

        return result;
    }

    json McpServer::handle_tools_call(const json &params) {
        if (!params.contains("name") || !params["name"].is_string()) {
            throw std::runtime_error("Missing or invalid 'name' parameter");
        }

        std::string tool_name = params["name"];
        json tool_params = params.contains("arguments") ? params["arguments"] : json::object();

        // Find tool and copy handler (release lock before blocking call)
        ToolHandler handler;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = tools_.find(tool_name);
            if (it == tools_.end()) {
                throw std::runtime_error("Tool not found: " + tool_name);
            }
            handler = it->second.handler;
        }

        // Call tool handler on IDA's main thread (required for thread safety)
        json tool_result = ida_mcp::execute_on_main_thread([&]() {
            return handler(tool_params);
        });

        // Wrap in MCP tool response format with isError support
        json result = {
            {"content", json::array({{
                {"type", "text"},
                {"text", tool_result.dump(2)}
            }})}
        };

        // Check if tool returned an error indicator
        if (tool_result.contains("isError") && tool_result["isError"].is_boolean()) {
            result["isError"] = tool_result["isError"];
        }

        // Support structured content if tool provides it
        if (tool_result.contains("structuredContent")) {
            result["structuredContent"] = tool_result["structuredContent"];
        }

        return result;
    }

    json McpServer::handle_ping(const json &params) {
        return json::object();
    }

    // ========================================================================
    // Resource Registration & Handlers (MCP 2025-11-25)
    // ========================================================================

    void McpServer::register_resource(const Resource &resource, ResourceHandler handler) {
        std::lock_guard<std::mutex> lock(mutex_);
        resources_[resource.uri] = ResourceEntry{resource, std::move(handler)};
    }

    void McpServer::register_resource_template(const ResourceTemplate &tmpl, ResourceHandler handler) {
        std::lock_guard<std::mutex> lock(mutex_);
        resource_templates_.push_back(ResourceTemplateEntry{tmpl, std::move(handler)});
    }

    std::vector<Resource> McpServer::get_resources() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<Resource> result;
        result.reserve(resources_.size());
        for (const auto &[uri, entry] : resources_) {
            result.push_back(entry.resource);
        }
        return result;
    }

    std::vector<ResourceTemplate> McpServer::get_resource_templates() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ResourceTemplate> result;
        result.reserve(resource_templates_.size());
        for (const auto &entry : resource_templates_) {
            result.push_back(entry.tmpl);
        }
        return result;
    }

    json McpServer::handle_resources_list(const json &params) {
        std::lock_guard<std::mutex> lock(mutex_);

        json resources_array = json::array();
        for (const auto &[uri, entry] : resources_) {
            resources_array.push_back(entry.resource.to_json());
        }

        return json{{"resources", resources_array}};
    }

    json McpServer::handle_resources_read(const json &params) {
        if (!params.contains("uri") || !params["uri"].is_string()) {
            throw std::runtime_error("Missing or invalid 'uri' parameter");
        }

        std::string uri = params["uri"];

        // Find resource handler - check concrete resources first, then templates
        ResourceHandler handler;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            
            // First, try exact match in concrete resources
            auto it = resources_.find(uri);
            if (it != resources_.end()) {
                handler = it->second.handler;
            } else {
                // Try to match against resource templates
                bool found = false;
                for (const auto &entry : resource_templates_) {
                    // Simple template matching: check if URI matches template pattern
                    // Template format: "scheme://path/{variable}" or similar
                    // For now, use prefix matching before the first '{' character
                    const std::string& tmpl = entry.tmpl.uri_template;
                    size_t brace_pos = tmpl.find('{');
                    if (brace_pos != std::string::npos) {
                        // Check if URI starts with the template prefix
                        std::string prefix = tmpl.substr(0, brace_pos);
                        if (uri.compare(0, prefix.length(), prefix) == 0) {
                            handler = entry.handler;
                            found = true;
                            break;
                        }
                    }
                }
                if (!found) {
                    throw std::runtime_error("Resource not found: " + uri);
                }
            }
        }

        // Execute handler on main thread
        ResourceContent content = ida_mcp::execute_on_main_thread([&]() {
            return handler(uri);
        });

        return json{{"contents", json::array({content.to_json()})}};
    }

    json McpServer::handle_resource_templates_list(const json &params) {
        std::lock_guard<std::mutex> lock(mutex_);

        json templates_array = json::array();
        for (const auto &entry : resource_templates_) {
            templates_array.push_back(entry.tmpl.to_json());
        }

        return json{{"resourceTemplates", templates_array}};
    }

    // ========================================================================
    // Prompt Registration & Handlers (MCP 2025-11-25)
    // ========================================================================

    void McpServer::register_prompt(const Prompt &prompt, PromptHandler handler) {
        std::lock_guard<std::mutex> lock(mutex_);
        prompts_[prompt.name] = PromptEntry{prompt, std::move(handler)};
    }

    std::vector<Prompt> McpServer::get_prompts() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<Prompt> result;
        result.reserve(prompts_.size());
        for (const auto &[name, entry] : prompts_) {
            result.push_back(entry.prompt);
        }
        return result;
    }

    json McpServer::handle_prompts_list(const json &params) {
        std::lock_guard<std::mutex> lock(mutex_);

        json prompts_array = json::array();
        for (const auto &[name, entry] : prompts_) {
            prompts_array.push_back(entry.prompt.to_json());
        }

        return json{{"prompts", prompts_array}};
    }

    json McpServer::handle_prompts_get(const json &params) {
        if (!params.contains("name") || !params["name"].is_string()) {
            throw std::runtime_error("Missing or invalid 'name' parameter");
        }

        std::string prompt_name = params["name"];
        json prompt_args = params.contains("arguments") ? params["arguments"] : json::object();

        // Find prompt handler
        PromptHandler handler;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = prompts_.find(prompt_name);
            if (it == prompts_.end()) {
                throw std::runtime_error("Prompt not found: " + prompt_name);
            }
            handler = it->second.handler;
        }

        // Execute handler on main thread
        std::vector<PromptMessage> messages = ida_mcp::execute_on_main_thread([&]() {
            return handler(prompt_args);
        });

        json messages_array = json::array();
        for (const auto &msg : messages) {
            messages_array.push_back(msg.to_json());
        }

        return json{{"messages", messages_array}};
    }

    // ========================================================================
    // Logging API (MCP 2025-11-25)
    // ========================================================================

    void McpServer::set_logging_level(LoggingLevel level) {
        std::lock_guard<std::mutex> lock(mutex_);
        logging_level_ = level;
    }

    LoggingLevel McpServer::get_logging_level() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return logging_level_;
    }

    json McpServer::handle_logging_set_level(const json &params) {
        if (!params.contains("level") || !params["level"].is_string()) {
            throw std::runtime_error("Missing or invalid 'level' parameter");
        }

        std::string level_str = params["level"];
        auto level_opt = logging_level_from_string(level_str);
        if (!level_opt.has_value()) {
            throw std::runtime_error("Invalid logging level: " + level_str);
        }

        set_logging_level(level_opt.value());

        return json::object();  // Empty result on success
    }

    // ========================================================================
    // Cancellation Handler (MCP 2025-11-25)
    // ========================================================================

    void McpServer::handle_cancelled(const json &params) {
        if (!params.contains("requestId")) {
            return;  // Invalid cancellation notification
        }

        std::lock_guard<std::mutex> lock(mutex_);
        
        // Enforce bounded size to prevent memory growth
        // Remove oldest entries if we've hit the limit
        while (cancelled_requests_.size() >= MAX_CANCELLED_REQUESTS) {
            cancelled_requests_.erase(cancelled_requests_.begin());
        }
        
        cancelled_requests_.insert(params["requestId"]);
    }

} // namespace ida_mcp::mcp
