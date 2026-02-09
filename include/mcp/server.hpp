#pragma once

#include "common.hpp"
#include "mcp/protocol.hpp"
#include <map>
#include <mutex>

namespace ida_mcp::mcp {

class McpServer {
public:
    McpServer();
    ~McpServer();

    // Register a tool handler
    void register_tool(const ToolDefinition& def, ToolHandler handler);

    // Handle MCP request
    McpResponse handle_request(const McpRequest& request);

    // Get all registered tools
    std::vector<ToolDefinition> get_tools() const;

private:
    // Initialize built-in tools
    void init_tools();

    // Handle specific methods
    json handle_initialize(const json& params);
    json handle_tools_list(const json& params);
    json handle_tools_call(const json& params);
    json handle_ping(const json& params);

    // Tool registry
    struct ToolEntry {
        ToolDefinition definition;
        ToolHandler handler;
    };

    std::map<std::string, ToolEntry> tools_;
    mutable std::mutex mutex_;

    // Server capabilities
    json capabilities_;
};

} // namespace ida_mcp::mcp
