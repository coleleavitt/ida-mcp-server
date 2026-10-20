#include "tools/tools.hpp"
#include <search.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <ua.hpp>

namespace ida_mcp::tools::find_items {
    namespace {

        json make_result(ea_t found, const char *kind) {
            if (found == BADADDR) {
                return json{
                    {"found", false},
                    {"type", kind}
                };
            }
            qstring name;
            get_ea_name(&name, found);
            func_t *func = get_func(found);
            return json{
                {"found", true},
                {"address", format_ea(found)},
                {"type", kind},
                {"name", name.empty() ? json(nullptr) : json(name.c_str())},
                {"in_function", func != nullptr}
            };
        }

        json handle_find_code(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");
            int direction = params.value("direction", 1);
            int sflag = SEARCH_CASE | (direction >= 0 ? SEARCH_DOWN : SEARCH_UP);
            ea_t found = find_code(ea_opt.value(), sflag);
            return make_result(found, "code");
        }

        json handle_find_data(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");
            int direction = params.value("direction", 1);
            int sflag = SEARCH_CASE | (direction >= 0 ? SEARCH_DOWN : SEARCH_UP);
            ea_t found = find_data(ea_opt.value(), sflag);
            return make_result(found, "data");
        }

        json handle_find_unknown(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");
            int direction = params.value("direction", 1);
            int sflag = SEARCH_CASE | (direction >= 0 ? SEARCH_DOWN : SEARCH_UP);
            ea_t found = find_unknown(ea_opt.value(), sflag);
            return make_result(found, "unknown");
        }

        json handle_find_defined(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");
            int direction = params.value("direction", 1);
            int sflag = SEARCH_CASE | (direction >= 0 ? SEARCH_DOWN : SEARCH_UP);
            ea_t found = find_defined(ea_opt.value(), sflag);
            return make_result(found, "defined");
        }

        json handle_find_not_func(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");
            int direction = params.value("direction", 1);
            int sflag = SEARCH_CASE | (direction >= 0 ? SEARCH_DOWN : SEARCH_UP);
            ea_t found = find_not_func(ea_opt.value(), sflag);
            return make_result(found, "not_in_function");
        }

        json handle_find_imm(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");
            auto val_opt = parse_ea(params["value"]);
            if (!val_opt) throw std::runtime_error("Invalid value");
            int direction = params.value("direction", 1);
            int sflag = SEARCH_CASE | (direction >= 0 ? SEARCH_DOWN : SEARCH_UP);
            ea_t found = find_imm(ea_opt.value(), sflag, val_opt.value());
            return make_result(found, "immediate_value");
        }

        json handle_find_notype(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");
            int direction = params.value("direction", 1);
            int sflag = SEARCH_CASE | (direction >= 0 ? SEARCH_DOWN : SEARCH_UP);
            ea_t found = find_notype(ea_opt.value(), sflag);
            return make_result(found, "no_type_info");
        }
    }

    void register_tools(mcp::McpServer &server) {
        json addr_schema = json{
            {"type", "object"},
            {"properties", {
                {"address", {{"type", "string"}, {"description", "Starting hex address"}}},
                {"direction", {{"type", "integer"}, {"description", "1=forward (default), -1=backward"}}}
            }},
            {"required", json::array({"address"})}
        };

        auto reg = [&](const char *name, const char *desc, auto handler) {
            mcp::ToolDefinition def;
            def.name = name;
            def.description = desc;
            def.input_schema = addr_schema;
            server.register_tool(def, handler);
        };

        reg("find_code", "Find next/prev code (instruction) address", handle_find_code);
        reg("find_data", "Find next/prev data item address", handle_find_data);
        reg("find_unknown", "Find next/prev undefined/unexplored address", handle_find_unknown);
        reg("find_defined", "Find next/prev defined (code or data) address", handle_find_defined);
        reg("find_not_func", "Find next/prev address not inside any function (orphan code/data)", handle_find_not_func);
        reg("find_notype", "Find next/prev address without type information", handle_find_notype);

        {
            mcp::ToolDefinition def;
            def.name = "find_imm";
            def.description = "Find next/prev occurrence of an immediate value in instructions";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Starting hex address"}}},
                    {"value", {{"type", "string"}, {"description", "Immediate value to search for (hex)"}}},
                    {"direction", {{"type", "integer"}, {"description", "1=forward (default), -1=backward"}}}
                }},
                {"required", json::array({"address", "value"})}
            };
            server.register_tool(def, handle_find_imm);
        }
    }
}
