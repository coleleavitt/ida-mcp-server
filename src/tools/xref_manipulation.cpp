#include "tools/tools.hpp"
#include <xref.hpp>
#include <funcs.hpp>
#include <bytes.hpp>
#include <lines.hpp>
#include <name.hpp>
#include <auto.hpp>

namespace ida_mcp::tools::xref_manipulation {
    namespace {
        json handle_add_cref(const json &params) {
            auto from_opt = parse_ea(params["from"]);
            auto to_opt = parse_ea(params["to"]);
            if (!from_opt || !to_opt) throw std::runtime_error("Invalid address");

            int type = params.value("type", (int)fl_JN);
            bool ok = add_cref(from_opt.value(), to_opt.value(), (cref_t)type);

            return json{
                {"from", format_ea(from_opt.value())},
                {"to", format_ea(to_opt.value())},
                {"type", type},
                {"success", ok}
            };
        }

        json handle_add_dref(const json &params) {
            auto from_opt = parse_ea(params["from"]);
            auto to_opt = parse_ea(params["to"]);
            if (!from_opt || !to_opt) throw std::runtime_error("Invalid address");

            int type = params.value("type", (int)dr_O);
            bool ok = add_dref(from_opt.value(), to_opt.value(), (dref_t)type);

            return json{
                {"from", format_ea(from_opt.value())},
                {"to", format_ea(to_opt.value())},
                {"type", type},
                {"success", ok}
            };
        }

        json handle_del_cref(const json &params) {
            auto from_opt = parse_ea(params["from"]);
            auto to_opt = parse_ea(params["to"]);
            if (!from_opt || !to_opt) throw std::runtime_error("Invalid address");

            bool expand = params.value("expand", false);
            bool ok = del_cref(from_opt.value(), to_opt.value(), expand);

            return json{
                {"from", format_ea(from_opt.value())},
                {"to", format_ea(to_opt.value())},
                {"success", ok}
            };
        }

        json handle_del_dref(const json &params) {
            auto from_opt = parse_ea(params["from"]);
            auto to_opt = parse_ea(params["to"]);
            if (!from_opt || !to_opt) throw std::runtime_error("Invalid address");

            del_dref(from_opt.value(), to_opt.value());

            return json{
                {"from", format_ea(from_opt.value())},
                {"to", format_ea(to_opt.value())},
                {"success", true}
            };
        }

        json handle_add_func(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");

            ea_t end = BADADDR;
            if (params.contains("end")) {
                auto end_opt = parse_ea(params["end"]);
                if (end_opt) end = end_opt.value();
            }

            bool ok = add_func(ea_opt.value(), end);

            qstring name;
            if (ok) get_func_name(&name, ea_opt.value());

            return json{
                {"address", format_ea(ea_opt.value())},
                {"end", end != BADADDR ? json(format_ea(end)) : json("auto")},
                {"success", ok},
                {"name", ok && !name.empty() ? json(name.c_str()) : json(nullptr)}
            };
        }

        json handle_del_func(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");

            func_t *func = get_func(ea_opt.value());
            if (!func) throw std::runtime_error("No function at " + format_ea(ea_opt.value()));

            qstring name;
            get_func_name(&name, func->start_ea);
            bool ok = del_func(ea_opt.value());

            return json{
                {"address", format_ea(ea_opt.value())},
                {"deleted_name", name.c_str()},
                {"success", ok}
            };
        }

        json handle_set_func_bounds(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");

            func_t *func = get_func(ea_opt.value());
            if (!func) throw std::runtime_error("No function at " + format_ea(ea_opt.value()));

            json result;
            result["address"] = format_ea(func->start_ea);

            if (params.contains("new_start")) {
                auto start_opt = parse_ea(params["new_start"]);
                if (start_opt) {
                    bool ok = set_func_start(ea_opt.value(), start_opt.value());
                    result["set_start"] = ok;
                    result["new_start"] = format_ea(start_opt.value());
                }
            }

            if (params.contains("new_end")) {
                auto end_opt = parse_ea(params["new_end"]);
                if (end_opt) {
                    bool ok = set_func_end(ea_opt.value(), end_opt.value());
                    result["set_end"] = ok;
                    result["new_end"] = format_ea(end_opt.value());
                }
            }

            return result;
        }

        json handle_set_item_color(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");

            if (params.contains("color")) {
                bgcolor_t color = params["color"].get<uint32_t>();
                set_item_color(ea_opt.value(), color);
                return json{{"address", format_ea(ea_opt.value())}, {"color", color}, {"action", "set"}};
            } else {
                del_item_color(ea_opt.value());
                return json{{"address", format_ea(ea_opt.value())}, {"action", "cleared"}};
            }
        }

        json handle_get_item_color(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");

            bgcolor_t color = get_item_color(ea_opt.value());

            return json{
                {"address", format_ea(ea_opt.value())},
                {"color", color != DEFCOLOR ? json(color) : json(nullptr)},
                {"has_custom_color", color != DEFCOLOR}
            };
        }

        json handle_add_hidden_range(const json &params) {
            auto start_opt = parse_ea(params["start"]);
            auto end_opt = parse_ea(params["end"]);
            if (!start_opt || !end_opt) throw std::runtime_error("Invalid address");

            std::string desc = params.value("description", "");
            std::string header = params.value("header", "");
            std::string footer = params.value("footer", "");
            bgcolor_t color = params.value("color", DEFCOLOR);

            bool ok = add_hidden_range(
                start_opt.value(), end_opt.value(),
                desc.c_str(), header.c_str(), footer.c_str(), color);

            return json{
                {"start", format_ea(start_opt.value())},
                {"end", format_ea(end_opt.value())},
                {"success", ok}
            };
        }

        json handle_get_extra_cmt(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");
            ea_t ea = ea_opt.value();

            json anterior = json::array();
            json posterior = json::array();

            for (int i = 0; i < 1000; i++) {
                qstring line;
                ssize_t len = get_extra_cmt(&line, ea, E_PREV + i);
                if (len < 0) break;
                anterior.push_back(line.c_str());
            }

            for (int i = 0; i < 1000; i++) {
                qstring line;
                ssize_t len = get_extra_cmt(&line, ea, E_NEXT + i);
                if (len < 0) break;
                posterior.push_back(line.c_str());
            }

            return json{
                {"address", format_ea(ea)},
                {"anterior", anterior},
                {"posterior", posterior}
            };
        }

        json handle_set_extra_cmt(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");
            ea_t ea = ea_opt.value();

            std::string text = params["text"].get<std::string>();
            std::string position = params.value("position", "anterior");

            int line_idx = params.value("line", 0);
            int base = (position == "posterior") ? E_NEXT : E_PREV;

            update_extra_cmt(ea, base + line_idx, text.c_str());

            return json{
                {"address", format_ea(ea)},
                {"position", position},
                {"line", line_idx},
                {"success", true}
            };
        }

        json handle_reanalyze(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");
            ea_t ea = ea_opt.value();

            asize_t size = params.value("size", 1);

            auto_mark_range(ea, ea + size, AU_USED);

            return json{
                {"address", format_ea(ea)},
                {"size", size},
                {"success", true}
            };
        }
    }

    void register_tools(mcp::McpServer &server) {
        auto make_addr_schema = [](std::initializer_list<std::pair<const char*, json>> extra = {}) {
            json props = {{"address", {{"type", "string"}, {"description", "Hex address"}}}};
            for (auto &[k, v] : extra) props[k] = v;
            return json{{"type", "object"}, {"properties", props}, {"required", json::array({"address"})}};
        };

        auto reg = [&](const char *name, const char *desc, const json &schema, auto handler) {
            mcp::ToolDefinition def;
            def.name = name;
            def.description = desc;
            def.input_schema = schema;
            server.register_tool(def, handler);
        };

        json from_to_schema = json{
            {"type", "object"},
            {"properties", {
                {"from", {{"type", "string"}, {"description", "Source hex address"}}},
                {"to", {{"type", "string"}, {"description", "Target hex address"}}},
                {"type", {{"type", "integer"}, {"description", "Xref type (optional)"}}}
            }},
            {"required", json::array({"from", "to"})}
        };

        reg("add_code_xref", "Add a code cross-reference between two addresses", from_to_schema, handle_add_cref);
        reg("add_data_xref", "Add a data cross-reference between two addresses", from_to_schema, handle_add_dref);
        reg("del_code_xref", "Delete a code cross-reference", from_to_schema, handle_del_cref);
        reg("del_data_xref", "Delete a data cross-reference", from_to_schema, handle_del_dref);

        {
            json schema = json{
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Function start address"}}},
                    {"end", {{"type", "string"}, {"description", "Function end address (auto-detect if omitted)"}}}
                }},
                {"required", json::array({"address"})}
            };
            reg("create_function", "Create a new function at address", schema, handle_add_func);
        }

        reg("delete_function", "Delete a function", make_addr_schema(), handle_del_func);

        {
            json schema = json{
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Address within the function"}}},
                    {"new_start", {{"type", "string"}, {"description", "New start address"}}},
                    {"new_end", {{"type", "string"}, {"description", "New end address"}}}
                }},
                {"required", json::array({"address"})}
            };
            reg("set_function_bounds", "Change function start and/or end address", schema, handle_set_func_bounds);
        }

        {
            json schema = json{
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Hex address"}}},
                    {"color", {{"type", "integer"}, {"description", "BGR color value (omit to clear color)"}}}
                }},
                {"required", json::array({"address"})}
            };
            reg("set_item_color", "Set background color for a disassembly item (for visual marking)", schema, handle_set_item_color);
        }

        reg("get_item_color", "Get the custom background color of a disassembly item", make_addr_schema(), handle_get_item_color);

        {
            json schema = json{
                {"type", "object"},
                {"properties", {
                    {"start", {{"type", "string"}, {"description", "Start hex address"}}},
                    {"end", {{"type", "string"}, {"description", "End hex address"}}},
                    {"description", {{"type", "string"}, {"description", "Description text"}}},
                    {"header", {{"type", "string"}, {"description", "Header shown when collapsed"}}},
                    {"footer", {{"type", "string"}, {"description", "Footer text"}}},
                    {"color", {{"type", "integer"}, {"description", "Background color (BGR)"}}}
                }},
                {"required", json::array({"start", "end"})}
            };
            reg("add_hidden_range", "Create a hidden/collapsible range in the listing", schema, handle_add_hidden_range);
        }

        reg("get_extra_comments", "Get anterior and posterior extra comments at address", make_addr_schema(), handle_get_extra_cmt);

        {
            json schema = json{
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Hex address"}}},
                    {"text", {{"type", "string"}, {"description", "Comment text"}}},
                    {"position", {{"type", "string"}, {"description", "anterior or posterior (default: anterior)"}}},
                    {"line", {{"type", "integer"}, {"description", "Line index within the comment block (default 0)"}}}
                }},
                {"required", json::array({"address", "text"})}
            };
            reg("set_extra_comment", "Set anterior or posterior extra comment at address", schema, handle_set_extra_cmt);
        }

        {
            json schema = json{
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Start hex address"}}},
                    {"size", {{"type", "integer"}, {"description", "Number of bytes to re-analyze (default 1)"}}}
                }},
                {"required", json::array({"address"})}
            };
            reg("reanalyze", "Mark address range for re-analysis by the auto-analyzer", schema, handle_reanalyze);
        }
    }
}
