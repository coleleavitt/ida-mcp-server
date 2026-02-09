#include "tools/tools.hpp"
#include <search.hpp>
#include <idp.hpp>
#include <lines.hpp>

namespace ida_mcp::tools::reg_search {
    namespace {
        json find_register_access_impl(const json &params) {
            std::string regname = params["register"].get<std::string>();
            int limit = params.value("limit", 50);

            ea_t start_ea = inf_get_min_ea();
            ea_t end_ea = inf_get_max_ea();

            if (params.contains("start_address")) {
                auto addr = parse_ea(params["start_address"]);
                if (!addr.has_value()) {
                    throw std::runtime_error("Invalid start_address");
                }
                start_ea = addr.value();
            }

            if (params.contains("end_address")) {
                auto addr = parse_ea(params["end_address"]);
                if (!addr.has_value()) {
                    throw std::runtime_error("Invalid end_address");
                }
                end_ea = addr.value();
            }

            int sflag = SEARCH_DOWN;

            std::string access_type = params.value("access_type", "any");
            if (access_type == "read") {
                sflag |= SEARCH_USE;
            } else if (access_type == "write") {
                sflag |= SEARCH_DEF;
            } else if (access_type == "any") {
                sflag |= SEARCH_USE | SEARCH_DEF;
            }

            json results = json::array();
            ea_t ea = start_ea;

            while (results.size() < static_cast<size_t>(limit)) {
                reg_access_t out;
                ea = find_reg_access(&out, ea, end_ea, regname.c_str(), sflag);

                if (ea == BADADDR || ea >= end_ea) {
                    break;
                }

                qstring disasm;
                generate_disasm_line(&disasm, ea, GENDSM_FORCE_CODE);
                qstring clean_disasm;
                tag_remove(&clean_disasm, disasm);

                std::string access_str;
                switch (out.access_type) {
                    case READ_ACCESS: access_str = "read"; break;
                    case WRITE_ACCESS: access_str = "write"; break;
                    case RW_ACCESS: access_str = "read_write"; break;
                    default: access_str = "unknown"; break;
                }

                func_t *func = get_func(ea);
                std::string func_name;
                if (func != nullptr) {
                    func_name = get_function_name(func);
                }

                results.push_back(json{
                    {"address", format_ea(ea)},
                    {"disassembly", clean_disasm.c_str()},
                    {"access_type", access_str},
                    {"operand", out.opnum},
                    {"function", func_name.empty() ? nullptr : json(func_name)}
                });

                ea = next_head(ea, end_ea);
                if (ea == BADADDR) {
                    break;
                }
            }

            return json{
                {"register", regname},
                {"access_filter", access_type},
                {"match_count", results.size()},
                {"truncated", results.size() >= static_cast<size_t>(limit)},
                {"results", results}
            };
        }
    }

    void register_tools(mcp::McpServer &server) {
        {
            mcp::ToolDefinition def;
            def.name = "find_register_access";
            def.description = "Search for instructions that read/write a specific register";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"register", {{"type", "string"}, {"description", "Register name (e.g., rax, eax, rbx)"}}},
                    {"access_type", {{"type", "string"}, {"description", "Type: read, write, or any (default: any)"}}},
                    {"start_address", {{"type", "string"}, {"description", "Hex start address"}}},
                    {"end_address", {{"type", "string"}, {"description", "Hex end address"}}},
                    {"limit", {{"type", "integer"}, {"description", "Max results (default: 50)"}}}
                }},
                {"required", json::array({"register"})}
            };
            server.register_tool(def, find_register_access_impl);
        }
    }
}
