#include "mcp/protocol.hpp"

namespace ida_mcp::mcp {
    std::optional<McpRequest> McpRequest::from_json(const json &j) {
        try {
            McpRequest req;

            if (!j.contains("jsonrpc") || j["jsonrpc"] != "2.0") {
                return std::nullopt;
            }
            req.jsonrpc = "2.0";

            if (j.contains("id")) {
                // JSON-RPC 2.0: id MUST be a String, Number (incl. fractional), or Null.
                const json &jid = j["id"];
                if (jid.is_number() || jid.is_string() || jid.is_null()) {
                    req.id = jid;
                } else {
                    // Present but of an invalid type (boolean/array/object): this is a
                    // malformed request, not a notification. Reject so the caller emits
                    // an INVALID_REQUEST error instead of silently dropping the id.
                    return std::nullopt;
                }
            }

            if (!j.contains("method") || !j["method"].is_string()) {
                return std::nullopt;
            }
            req.method = j["method"];

            if (j.contains("params")) {
                req.params = j["params"];
            } else {
                req.params = json::object();
            }

            return req;
        } catch (const json::exception &) {
            return std::nullopt;
        }
    }

    json McpResponse::to_json() const {
        json j;
        j["jsonrpc"] = jsonrpc;

        if (id.has_value()) {
            j["id"] = id.value();
        }

        if (result.has_value()) {
            j["result"] = result.value();
        }

        if (error_data.has_value()) {
            j["error"] = error_data.value();
        }

        return j;
    }
} // namespace ida_mcp::mcp
