#include "tools/tools.hpp"

extern "C" {
    sval_t get_wide_value(ea_t ea);
    void set_wide_value(ea_t ea, sval_t value);
    void del_wide_value(ea_t ea);
}

namespace ida_mcp::tools::wide_values {
    namespace {
        json get_wide_value_impl(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            sval_t val = ::get_wide_value(ea);

            json result = {
                {"address", format_ea(ea)},
                {"has_value", val != -1}
            };

            if (val != -1) {
                result["value"] = static_cast<int64_t>(val);
                char hex[32];
                qsnprintf(hex, sizeof(hex), "0x%llX", (uint64)val);
                result["value_hex"] = hex;
            }

            return result;
        }

        json set_wide_value_impl(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            sval_t value = 0;
            if (params["value"].is_string()) {
                auto val_opt = parse_ea(params["value"]);
                if (!val_opt.has_value()) {
                    throw std::runtime_error("Invalid value format");
                }
                value = static_cast<sval_t>(val_opt.value());
            } else {
                value = params["value"].get<sval_t>();
            }

            ::set_wide_value(ea, value);

            return json{
                {"address", format_ea(ea)},
                {"value", static_cast<int64_t>(value)},
                {"success", true}
            };
        }

        json del_wide_value_impl(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            ::del_wide_value(ea);

            return json{
                {"address", format_ea(ea)},
                {"success", true}
            };
        }
    }

    void register_tools(mcp::McpServer &server) {
        {
            mcp::ToolDefinition def;
            def.name = "get_wide_value";
            def.description = "Get the 64-bit wide value stored at an address in the IDA database. "
                "Returns -1 if no value is set.";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Hex address"}}}
                }},
                {"required", json::array({"address"})}
            };
            server.register_tool(def, get_wide_value_impl);
        }

        {
            mcp::ToolDefinition def;
            def.name = "set_wide_value";
            def.description = "Set a 64-bit wide value at an address in the IDA database. "
                "Accepts integer or hex string values.";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Hex address"}}},
                    {"value", {{"description", "Value to store (integer or hex string)"}}}
                }},
                {"required", json::array({"address", "value"})}
            };
            server.register_tool(def, set_wide_value_impl);
        }

        {
            mcp::ToolDefinition def;
            def.name = "del_wide_value";
            def.description = "Delete the wide value at an address";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Hex address"}}}
                }},
                {"required", json::array({"address"})}
            };
            server.register_tool(def, del_wide_value_impl);
        }
    }
}
