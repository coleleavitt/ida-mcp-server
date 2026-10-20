#include "tools/tools.hpp"
#include <nalt.hpp>
#include <xref.hpp>

// 9.3-only jump table info APIs — C-linkage, discovered via Hex-Rays decompilation
extern "C" {
ssize_t get_jumptable_info(ea_t out[2], ea_t ea);

void set_jumptable_info(ea_t ea, const ea_t info[2]);

void del_jumptable_info(ea_t ea);
}

namespace ida_mcp::tools::jumptables {
    namespace {
        json set_switch_info_impl(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            switch_info_t si;

            if (params.contains("jump_table") && !params["jump_table"].is_null()) {
                auto jt_opt = parse_ea(params["jump_table"]);
                if (jt_opt.has_value()) {
                    si.jumps = jt_opt.value();
                }
            }

            if (params.contains("ncases") && !params["ncases"].is_null()) {
                si.ncases = static_cast<ushort>(params["ncases"].get<int>());
            }

            if (params.contains("default_jump") && !params["default_jump"].is_null()) {
                auto dj_opt = parse_ea(params["default_jump"]);
                if (dj_opt.has_value()) {
                    si.defjump = dj_opt.value();
                }
            }

            if (params.contains("start_ea") && !params["start_ea"].is_null()) {
                auto se_opt = parse_ea(params["start_ea"]);
                if (se_opt.has_value()) {
                    si.startea = se_opt.value();
                }
            }

            if (params.contains("lowcase") && !params["lowcase"].is_null()) {
                si.lowcase = params["lowcase"].get<uint64_t>();
            }

            if (params.contains("element_base") && !params["element_base"].is_null()) {
                auto eb_opt = parse_ea(params["element_base"]);
                if (eb_opt.has_value()) {
                    si.set_elbase(eb_opt.value());
                }
            }

            uint32 flags = 0;
            if (params.contains("sparse") && params["sparse"].get<bool>()) {
                flags |= SWI_SPARSE;
            }
            if (params.contains("signed") && params["signed"].get<bool>()) {
                flags |= SWI_SIGNED;
            }
            if (params.contains("subtract") && params["subtract"].get<bool>()) {
                flags |= SWI_SUBTRACT;
            }
            si.flags |= flags;

            int jtable_size = 4;
            if (params.contains("jtable_element_size") && !params["jtable_element_size"].is_null()) {
                jtable_size = params["jtable_element_size"].get<int>();
            }
            si.set_jtable_element_size(jtable_size);

            ::set_switch_info(ea, si);

            return json{
                {"address", format_ea(ea)},
                {"jump_table", format_ea(si.jumps)},
                {"ncases", si.ncases},
                {"success", true}
            };
        }

        json del_switch_info_impl(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            switch_info_t si;
            ssize_t result = ::get_switch_info(&si, ea);
            if (result <= 0) {
                throw std::runtime_error("No switch info at " + format_ea(ea));
            }

            ::del_switch_info(ea);

            return json{
                {"address", format_ea(ea)},
                {"success", true}
            };
        }

        json create_switch_xrefs_impl(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            switch_info_t si;
            ssize_t result = ::get_switch_info(&si, ea);
            if (result <= 0) {
                throw std::runtime_error("No switch info at " + format_ea(ea));
            }

            ::create_switch_table(ea, si);

            return json{
                {"address", format_ea(ea)},
                {"jump_table", format_ea(si.jumps)},
                {"success", true}
            };
        }

        json get_jumptable_info_impl(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            ea_t out[2] = {BADADDR, 0};
            ssize_t result = ::get_jumptable_info(out, ea);

            if (result < 0) {
                return json{
                    {"address", format_ea(ea)},
                    {"has_info", false}
                };
            }

            return json{
                {"address", format_ea(ea)},
                {"has_info", true},
                {"table_address", format_ea(out[0])},
                {"table_size", static_cast<uint64_t>(out[1])}
            };
        }

        json set_jumptable_info_impl(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            auto table_opt = parse_ea(params["table_address"]);
            if (!table_opt.has_value()) {
                throw std::runtime_error("Invalid table_address format");
            }

            ea_t info[2];
            info[0] = table_opt.value();
            info[1] = params["table_size"].get<ea_t>();

            ::set_jumptable_info(ea, info);

            return json{
                {"address", format_ea(ea)},
                {"table_address", format_ea(info[0])},
                {"table_size", static_cast<uint64_t>(info[1])},
                {"success", true}
            };
        }

        json del_jumptable_info_impl(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            ::del_jumptable_info(ea);

            return json{
                {"address", format_ea(ea)},
                {"success", true}
            };
        }
    }

    void register_tools(mcp::McpServer &server) { {
            mcp::ToolDefinition def;
            def.name = "set_switch_info";
            def.description = "Create or modify a switch/jump table definition at an address. "
                    "Requires at minimum: address (the indirect jump), jump_table (table start), and ncases.";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "address",
                            {{"type", "string"}, {"description", "Hex address of the indirect jump instruction"}}
                        },
                        {"jump_table", {{"type", "string"}, {"description", "Hex address of the jump table start"}}},
                        {"ncases", {{"type", "integer"}, {"description", "Number of cases (excluding default)"}}},
                        {
                            "default_jump",
                            {{"type", "string"}, {"description", "Hex address of default case (optional)"}}
                        },
                        {"start_ea", {{"type", "string"}, {"description", "Start of switch idiom (optional)"}}},
                        {"lowcase", {{"type", "integer"}, {"description", "Lowest case value (optional, default 0)"}}},
                        {
                            "element_base",
                            {{"type", "string"}, {"description", "Element base address for relative tables (optional)"}}
                        },
                        {
                            "jtable_element_size",
                            {{"type", "integer"}, {"description", "Jump table element size: 1, 2, 4, or 8 (default 4)"}}
                        },
                        {
                            "sparse",
                            {{"type", "boolean"}, {"description", "Whether switch is sparse (has value table)"}}
                        },
                        {"signed", {{"type", "boolean"}, {"description", "Whether jump table entries are signed"}}},
                        {
                            "subtract",
                            {{"type", "boolean"}, {"description", "Whether values are subtracted from elbase"}}
                        }
                    }
                },
                {"required", json::array({"address", "jump_table", "ncases"})}
            };
            server.register_tool(def, set_switch_info_impl);
        } {
            mcp::ToolDefinition def;
            def.name = "del_switch_info";
            def.description = "Delete a switch/jump table definition at an address";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {"address", {{"type", "string"}, {"description", "Hex address of the switch instruction"}}}
                    }
                },
                {"required", json::array({"address"})}
            };
            server.register_tool(def, del_switch_info_impl);
        } {
            mcp::ToolDefinition def;
            def.name = "create_switch_xrefs";
            def.description = "Create cross-references and data items for an existing switch table. "
                    "Call after set_switch_info to make IDA recognize the table structure.";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {"address", {{"type", "string"}, {"description", "Hex address of the switch instruction"}}}
                    }
                },
                {"required", json::array({"address"})}
            };
            server.register_tool(def, create_switch_xrefs_impl);
        } {
            mcp::ToolDefinition def;
            def.name = "get_jumptable_info";
            def.description = "Get jump table info (table address and size) stored at an address. "
                    "IDA 9.3+ only. Returns table_address and table_size if info exists.";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {"address", {{"type", "string"}, {"description", "Hex address to query"}}}
                    }
                },
                {"required", json::array({"address"})}
            };
            server.register_tool(def, get_jumptable_info_impl);
        } {
            mcp::ToolDefinition def;
            def.name = "set_jumptable_info";
            def.description = "Store jump table info (table address and size) at an address. "
                    "IDA 9.3+ only.";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {"address", {{"type", "string"}, {"description", "Hex address of the jump instruction"}}},
                        {"table_address", {{"type", "string"}, {"description", "Hex address of the jump table"}}},
                        {"table_size", {{"type", "integer"}, {"description", "Number of entries in the table"}}}
                    }
                },
                {"required", json::array({"address", "table_address", "table_size"})}
            };
            server.register_tool(def, set_jumptable_info_impl);
        } {
            mcp::ToolDefinition def;
            def.name = "del_jumptable_info";
            def.description = "Delete jump table info at an address. IDA 9.3+ only.";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {"address", {{"type", "string"}, {"description", "Hex address"}}}
                    }
                },
                {"required", json::array({"address"})}
            };
            server.register_tool(def, del_jumptable_info_impl);
        }
    }
}
