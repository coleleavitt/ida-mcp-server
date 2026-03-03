#pragma once

#include "common.hpp"
#include <variant>

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
    std::optional<json> id;  // Can be int64_t or string per JSON-RPC 2.0 spec
    std::string method;
    json params;

    static std::optional<McpRequest> from_json(const json& j);
};

struct McpResponse {
    std::string jsonrpc = "2.0";
    std::optional<json> id;  // Can be int64_t or string per JSON-RPC 2.0 spec
    std::optional<json> result;
    std::optional<json> error_data;  // Renamed from 'error' to avoid IDA SDK macro conflict
    bool is_notification = false;     // True when the request was a notification (no response needed)

    json to_json() const;

    // Helper to create success response
    static McpResponse success(json id, json result) {
        McpResponse resp;
        resp.id = std::move(id);
        resp.result = std::move(result);
        return resp;
    }

    // Helper to create a notification acknowledgement (no JSON-RPC response body)
    static McpResponse notification_accepted() {
        McpResponse resp;
        resp.is_notification = true;
        return resp;
    }

    // Helper to create error response
    static McpResponse make_error(json id, int code, std::string message) {
        McpResponse resp;
        resp.id = std::move(id);
        resp.error_data = json{
            {"code", code},
            {"message", std::move(message)}
        };
        return resp;
    }
};

// MCP error codes (JSON-RPC 2.0 standard + MCP extensions)
namespace error_codes {
    constexpr int PARSE_ERROR = -32700;
    constexpr int INVALID_REQUEST = -32600;
    constexpr int METHOD_NOT_FOUND = -32601;
    constexpr int INVALID_PARAMS = -32602;
    constexpr int INTERNAL_ERROR = -32603;
    // MCP-specific error codes
    constexpr int URL_ELICITATION_REQUIRED = -32042;
}

// ============================================================================
// Tool Annotations (MCP 2025-11-25)
// Hints about tool behavior - advisory only, not guaranteed
// ============================================================================
struct ToolAnnotations {
    std::optional<std::string> title;           // Human-readable display name
    std::optional<bool> read_only_hint;         // Tool does not modify environment
    std::optional<bool> destructive_hint;       // Tool may perform destructive updates
    std::optional<bool> idempotent_hint;        // Repeated calls have no additional effect
    std::optional<bool> open_world_hint;        // Tool may interact with external entities

    json to_json() const {
        json j = json::object();
        if (title) j["title"] = *title;
        if (read_only_hint) j["readOnlyHint"] = *read_only_hint;
        if (destructive_hint) j["destructiveHint"] = *destructive_hint;
        if (idempotent_hint) j["idempotentHint"] = *idempotent_hint;
        if (open_world_hint) j["openWorldHint"] = *open_world_hint;
        return j;
    }
};

// ============================================================================
// Tool Definition (MCP 2025-11-25)
// ============================================================================
struct ToolDefinition {
    std::string name;
    std::string description;
    json input_schema;                          // JSON Schema for input parameters
    std::optional<json> output_schema;          // JSON Schema for structured output (new in 2025)
    std::optional<ToolAnnotations> annotations; // Behavior hints (new in 2025)

    json to_json() const {
        json j = {
            {"name", name},
            {"description", description},
            {"inputSchema", input_schema}
        };
        if (output_schema) j["outputSchema"] = *output_schema;
        if (annotations) j["annotations"] = annotations->to_json();
        return j;
    }
};

// Tool handler function type
using ToolHandler = std::function<json(const json& params)>;

// ============================================================================
// Content Types (MCP 2025-11-25)
// ============================================================================

// Role for content audience
enum class Role { User, Assistant };

// Annotations for content metadata
struct Annotations {
    std::optional<std::vector<Role>> audience;  // Who the content is for
    std::optional<double> priority;             // 0.0 (least) to 1.0 (most important)
    std::optional<std::string> last_modified;   // ISO 8601 timestamp

    json to_json() const {
        json j = json::object();
        if (audience) {
            json arr = json::array();
            for (const auto& r : *audience) {
                arr.push_back(r == Role::User ? "user" : "assistant");
            }
            j["audience"] = arr;
        }
        if (priority) j["priority"] = *priority;
        if (last_modified) j["lastModified"] = *last_modified;
        return j;
    }
};

// Text content block
struct TextContent {
    std::string text;
    std::optional<Annotations> annotations;

    json to_json() const {
        json j = {{"type", "text"}, {"text", text}};
        if (annotations) j["annotations"] = annotations->to_json();
        return j;
    }
};

// Image content block
struct ImageContent {
    std::string data;      // Base64-encoded image data
    std::string mime_type; // e.g., "image/png"
    std::optional<Annotations> annotations;

    json to_json() const {
        json j = {{"type", "image"}, {"data", data}, {"mimeType", mime_type}};
        if (annotations) j["annotations"] = annotations->to_json();
        return j;
    }
};

// ============================================================================
// Resource Types (MCP 2025-11-25)
// ============================================================================
struct Resource {
    std::string uri;                            // Unique resource identifier
    std::string name;                           // Human-readable name
    std::optional<std::string> description;
    std::optional<std::string> mime_type;
    std::optional<Annotations> annotations;

    json to_json() const {
        json j = {{"uri", uri}, {"name", name}};
        if (description) j["description"] = *description;
        if (mime_type) j["mimeType"] = *mime_type;
        if (annotations) j["annotations"] = annotations->to_json();
        return j;
    }
};

// Resource template (RFC 6570 URI templates)
struct ResourceTemplate {
    std::string uri_template;                   // URI template string
    std::string name;
    std::optional<std::string> description;
    std::optional<std::string> mime_type;

    json to_json() const {
        json j = {{"uriTemplate", uri_template}, {"name", name}};
        if (description) j["description"] = *description;
        if (mime_type) j["mimeType"] = *mime_type;
        return j;
    }
};

// Resource content (text or blob)
struct ResourceContent {
    std::string uri;
    std::optional<std::string> mime_type;
    std::optional<std::string> text;           // For text resources
    std::optional<std::string> blob;           // For binary resources (base64)

    json to_json() const {
        json j = {{"uri", uri}};
        if (mime_type) j["mimeType"] = *mime_type;
        if (text) j["text"] = *text;
        if (blob) j["blob"] = *blob;
        return j;
    }
};

// ============================================================================
// Prompt Types (MCP 2025-11-25)
// ============================================================================
struct PromptArgument {
    std::string name;
    std::optional<std::string> description;
    std::optional<bool> required;

    json to_json() const {
        json j = {{"name", name}};
        if (description) j["description"] = *description;
        if (required) j["required"] = *required;
        return j;
    }
};

struct Prompt {
    std::string name;
    std::optional<std::string> description;
    std::optional<std::vector<PromptArgument>> arguments;

    json to_json() const {
        json j = {{"name", name}};
        if (description) j["description"] = *description;
        if (arguments) {
            json arr = json::array();
            for (const auto& arg : *arguments) {
                arr.push_back(arg.to_json());
            }
            j["arguments"] = arr;
        }
        return j;
    }
};

struct PromptMessage {
    Role role;
    json content;  // Can be TextContent, ImageContent, etc.

    json to_json() const {
        return json{
            {"role", role == Role::User ? "user" : "assistant"},
            {"content", content}
        };
    }
};

// ============================================================================
// Logging Types (MCP 2025-11-25)
// ============================================================================
enum class LoggingLevel {
    Debug,
    Info,
    Notice,
    Warning,
    Error,
    Critical,
    Alert,
    Emergency
};

inline std::string logging_level_to_string(LoggingLevel level) {
    switch (level) {
        case LoggingLevel::Debug: return "debug";
        case LoggingLevel::Info: return "info";
        case LoggingLevel::Notice: return "notice";
        case LoggingLevel::Warning: return "warning";
        case LoggingLevel::Error: return "error";
        case LoggingLevel::Critical: return "critical";
        case LoggingLevel::Alert: return "alert";
        case LoggingLevel::Emergency: return "emergency";
        default: return "info";
    }
}

inline LoggingLevel logging_level_from_string(const std::string& s) {
    if (s == "debug") return LoggingLevel::Debug;
    if (s == "info") return LoggingLevel::Info;
    if (s == "notice") return LoggingLevel::Notice;
    if (s == "warning") return LoggingLevel::Warning;
    if (s == "error") return LoggingLevel::Error;
    if (s == "critical") return LoggingLevel::Critical;
    if (s == "alert") return LoggingLevel::Alert;
    if (s == "emergency") return LoggingLevel::Emergency;
    return LoggingLevel::Info;
}

// ============================================================================
// Progress & Cancellation Types (MCP 2025-11-25)
// ============================================================================
using ProgressToken = std::variant<std::string, int64_t>;

struct ProgressNotification {
    ProgressToken progress_token;
    double progress;                            // Current progress value
    std::optional<double> total;                // Total expected (if known)
    std::optional<std::string> message;         // Human-readable status

    json to_json() const {
        json j = {{"progress", progress}};
        if (std::holds_alternative<std::string>(progress_token)) {
            j["progressToken"] = std::get<std::string>(progress_token);
        } else {
            j["progressToken"] = std::get<int64_t>(progress_token);
        }
        if (total) j["total"] = *total;
        if (message) j["message"] = *message;
        return j;
    }
};

struct CancelledNotification {
    std::optional<json> request_id;             // ID of request to cancel
    std::optional<std::string> reason;          // Why cancelled

    json to_json() const {
        json j = json::object();
        if (request_id) j["requestId"] = *request_id;
        if (reason) j["reason"] = *reason;
        return j;
    }
};

// ============================================================================
// Pagination Types (MCP 2025-11-25)
// ============================================================================
using Cursor = std::string;  // Opaque pagination cursor

// ============================================================================
// Handler function types
// ============================================================================
using ResourceHandler = std::function<ResourceContent(const std::string& uri)>;
using PromptHandler = std::function<std::vector<PromptMessage>(const json& arguments)>;
} // namespace ida_mcp::mcp
