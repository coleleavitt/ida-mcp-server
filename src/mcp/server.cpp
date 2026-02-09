#include "mcp/server.hpp"
#include "common.hpp"
#include <iostream>

namespace ida_mcp::mcp {
    McpServer::McpServer() {
        // Set server capabilities
        capabilities_ = json{
            {"tools", json::object()},
            {"resources", json::object()},
            {"prompts", json::object()}
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
        // Check if request has ID (responses only for requests with ID)
        if (!request.id.has_value()) {
            return McpResponse::make_error(0, error_codes::INVALID_REQUEST,
                                           "Request must have an id");
        }

        int64_t request_id = request.id.value();

        // Route to appropriate handler
        try {
            json result;

            if (request.method == "initialize") {
                result = handle_initialize(request.params);
            } else if (request.method == "tools/list") {
                result = handle_tools_list(request.params);
            } else if (request.method == "tools/call") {
                result = handle_tools_call(request.params);
            } else if (request.method == "ping") {
                result = handle_ping(request.params);
            } else {
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
            {"protocolVersion", "2024-11-05"},
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

        return json{
            {"tools", tools_array}
        };
    }

    json McpServer::handle_tools_call(const json &params) {
        if (!params.contains("name") || !params["name"].is_string()) {
            throw std::runtime_error("Missing or invalid 'name' parameter");
        }

        std::string tool_name = params["name"];
        json tool_params = params.contains("arguments") ? params["arguments"] : json::object();

        // Find and call tool
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = tools_.find(tool_name);
        if (it == tools_.end()) {
            throw std::runtime_error("Tool not found: " + tool_name);
        }

        // Call tool handler on IDA's main thread (required for thread safety)
        auto handler = it->second.handler;
        json tool_result = ida_mcp::execute_on_main_thread([&]() {
            return handler(tool_params);
        });

        // Wrap in MCP tool response format
        return json{
            {
                "content", json::array({
                    {
                        {"type", "text"},
                        {"text", tool_result.dump(2)}
                    }
                })
            }
        };
    }

    json McpServer::handle_ping(const json &params) {
        return json::object();
    }
} // namespace ida_mcp::mcp
