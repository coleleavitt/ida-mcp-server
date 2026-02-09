#pragma once

#include "common.hpp"

namespace ida_mcp::mcp {

// MCP message types
enum class MessageType {
    Initialize,
    ToolsList,
    ToolsCall,
    ResourcesList,
    ResourcesRead,
    PromptsList,
    PromptsGet,
    Ping,
    Unknown
};

// MCP request/response structures
struct McpRequest {
    std::string jsonrpc;
    std::optional<int64_t> id;
    std::string method;
    json params;

    static std::optional<McpRequest> from_json(const json& j);
};

struct McpResponse {
    std::string jsonrpc = "2.0";
    std::optional<int64_t> id;
    std::optional<json> result;
    std::optional<json> error_data;  // Renamed from 'error' to avoid IDA SDK macro conflict

    json to_json() const;

    // Helper to create success response
    static McpResponse success(int64_t id, json result) {
        McpResponse resp;
        resp.id = id;
        resp.result = std::move(result);
        return resp;
    }

    // Helper to create error response
    static McpResponse make_error(int64_t id, int code, std::string message) {
        McpResponse resp;
        resp.id = id;
        resp.error_data = json{
            {"code", code},
            {"message", std::move(message)}
        };
        return resp;
    }
};

// MCP error codes
namespace error_codes {
    constexpr int PARSE_ERROR = -32700;
    constexpr int INVALID_REQUEST = -32600;
    constexpr int METHOD_NOT_FOUND = -32601;
    constexpr int INVALID_PARAMS = -32602;
    constexpr int INTERNAL_ERROR = -32603;
}

// Tool definition
struct ToolDefinition {
    std::string name;
    std::string description;
    json input_schema;

    json to_json() const {
        return json{
            {"name", name},
            {"description", description},
            {"inputSchema", input_schema}
        };
    }
};

// Tool handler function type
using ToolHandler = std::function<json(const json& params)>;

} // namespace ida_mcp::mcp
