#pragma once

#include "common.hpp"
#include "mcp/protocol.hpp"
#include <map>
#include <mutex>
#include <set>

namespace ida_mcp::mcp {

class McpServer {
public:
    McpServer();
    ~McpServer();

    // ========================================================================
    // Tool Registration
    // ========================================================================
    void register_tool(const ToolDefinition& def, ToolHandler handler);
    std::vector<ToolDefinition> get_tools() const;

    // ========================================================================
    // Resource Registration (MCP 2025-11-25)
    // ========================================================================
    void register_resource(const Resource& resource, ResourceHandler handler);
    void register_resource_template(const ResourceTemplate& tmpl, ResourceHandler handler);
    std::vector<Resource> get_resources() const;
    std::vector<ResourceTemplate> get_resource_templates() const;

    // ========================================================================
    // Prompt Registration (MCP 2025-11-25)
    // ========================================================================
    void register_prompt(const Prompt& prompt, PromptHandler handler);
    std::vector<Prompt> get_prompts() const;

    // ========================================================================
    // Logging Configuration (MCP 2025-11-25)
    // ========================================================================
    void set_logging_level(LoggingLevel level);
    LoggingLevel get_logging_level() const;

    // ========================================================================
    // Request Handling
    // ========================================================================
    McpResponse handle_request(const McpRequest& request);

private:
    // Initialize built-in tools
    void init_tools();

    // Method handlers
    json handle_initialize(const json& params);
    json handle_tools_list(const json& params);
    json handle_tools_call(const json& params);
    json handle_ping(const json& params);
    json handle_resources_list(const json& params);
    json handle_resources_read(const json& params);
    json handle_resource_templates_list(const json& params);
    json handle_prompts_list(const json& params);
    json handle_prompts_get(const json& params);
    json handle_logging_set_level(const json& params);

    // Notification handlers
    void handle_cancelled(const json& params);

    // Tool registry
    struct ToolEntry {
        ToolDefinition definition;
        ToolHandler handler;
    };
    std::map<std::string, ToolEntry> tools_;

    // Resource registry
    struct ResourceEntry {
        Resource resource;
        ResourceHandler handler;
    };
    std::map<std::string, ResourceEntry> resources_;  // keyed by URI

    // Resource template registry
    struct ResourceTemplateEntry {
        ResourceTemplate tmpl;
        ResourceHandler handler;
    };
    std::vector<ResourceTemplateEntry> resource_templates_;

    // Prompt registry
    struct PromptEntry {
        Prompt prompt;
        PromptHandler handler;
    };
    std::map<std::string, PromptEntry> prompts_;

    // Logging state
    LoggingLevel logging_level_ = LoggingLevel::Info;

    // Cancelled request tracking (bounded to prevent memory growth)
    static constexpr size_t MAX_CANCELLED_REQUESTS = 1000;
    std::set<json> cancelled_requests_;

    mutable std::mutex mutex_;

    // Server capabilities
    json capabilities_;
};

} // namespace ida_mcp::mcp
