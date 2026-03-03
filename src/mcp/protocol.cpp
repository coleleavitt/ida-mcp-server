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
                // JSON-RPC 2.0 allows id to be String, Number, or Null
                if (j["id"].is_number_integer() || j["id"].is_string()) {
                    req.id = j["id"];
                } else if (j["id"].is_null()) {
                    req.id = nullptr;
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
