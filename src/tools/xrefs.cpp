#include "tools/tools.hpp"
#include <xref.hpp>

namespace ida_mcp::tools::xrefs {
    // Decode xref type to human-readable string
    static const char *decode_xref_type(bool is_code, uint8 xref_type) {
        if (is_code) {
            // Code reference types (cref_t)
            switch (xref_type) {
                case fl_CF: return "Call_Far";
                case fl_CN: return "Call_Near";
                case fl_JF: return "Jump_Far";
                case fl_JN: return "Jump_Near";
                case fl_F: return "Flow";
                default: return "Code_Unknown";
            }
        } else {
            // Data reference types (dref_t)
            switch (xref_type) {
                case dr_O: return "Data_Offset";
                case dr_W: return "Data_Write";
                case dr_R: return "Data_Read";
                case dr_T: return "Data_Text";
                case dr_I: return "Data_Informational";
                default: return "Data_Unknown";
            }
        }
    }

    // Build JSON object for an xref
    static json build_xref_json(const xrefblk_t &xb) {
        return json{
            {"from", format_ea(xb.from)},
            {"to", format_ea(xb.to)},
            {"type", decode_xref_type(xb.iscode, xb.type)},
            {"is_code", xb.iscode},
            {"user_defined", xb.user}
        };
    }

    // Get cross-references to an address
    static json get_xrefs_to(const json &params) {
        auto ea_opt = parse_ea(params["address"]);
        if (!ea_opt.has_value()) {
            throw std::runtime_error("Invalid address format");
        }
        ea_t ea = ea_opt.value();
        bool include_flow = params.value("include_flow", false);

        // Determine flags: skip flow xrefs unless requested
        int flags = include_flow ? XREF_ALL : XREF_FAR;

        json xrefs = json::array();
        xrefblk_t xb;

        for (bool ok = xb.first_to(ea, flags); ok; ok = xb.next_to()) {
            xrefs.push_back(build_xref_json(xb));
        }

        return json{
            {"address", format_ea(ea)},
            {"xref_count", xrefs.size()},
            {"include_flow", include_flow},
            {"xrefs", xrefs}
        };
    }

    // Get cross-references from an address
    static json get_xrefs_from(const json &params) {
        auto ea_opt = parse_ea(params["address"]);
        if (!ea_opt.has_value()) {
            throw std::runtime_error("Invalid address format");
        }
        ea_t ea = ea_opt.value();
        bool include_flow = params.value("include_flow", false);

        // Determine flags: skip flow xrefs unless requested
        int flags = include_flow ? XREF_ALL : XREF_FAR;

        json xrefs = json::array();
        xrefblk_t xb;

        for (bool ok = xb.first_from(ea, flags); ok; ok = xb.next_from()) {
            xrefs.push_back(build_xref_json(xb));
        }

        return json{
            {"address", format_ea(ea)},
            {"xref_count", xrefs.size()},
            {"include_flow", include_flow},
            {"xrefs", xrefs}
        };
    }

    // Xref manipulation functions commented out - potentially destructive operations
    // Uncomment if you need to modify the IDA database programmatically

    /*
    // Add a code cross-reference
    static json add_code_xref(const json& params) {
        ea_t from = parse_ea(params["from"]).value();
        ea_t to = parse_ea(params["to"]).value();
        std::string type_str = params["xref_type"].get<std::string>();

        // Parse xref type
        cref_t type;
        if (type_str == "call_near" || type_str == "Call_Near") {
            type = fl_CN;
        } else if (type_str == "call_far" || type_str == "Call_Far") {
            type = fl_CF;
        } else if (type_str == "jump_near" || type_str == "Jump_Near") {
            type = fl_JN;
        } else if (type_str == "jump_far" || type_str == "Jump_Far") {
            type = fl_JF;
        } else if (type_str == "flow" || type_str == "Flow") {
            type = fl_F;
        } else {
            throw std::runtime_error("Invalid code xref type: " + type_str + ". Valid types: call_near, call_far, jump_near, jump_far, flow");
        }

        bool success = add_cref(from, to, type);

        return json{
            {"success", success},
            {"from", format_ea(from)},
            {"to", format_ea(to)},
            {"xref_type", type_str}
        };
    }

    // Add a data cross-reference
    static json add_data_xref(const json& params) {
        ea_t from = parse_ea(params["from"]).value();
        ea_t to = parse_ea(params["to"]).value();
        std::string type_str = params["xref_type"].get<std::string>();

        // Parse xref type
        dref_t type;
        if (type_str == "offset" || type_str == "Data_Offset") {
            type = dr_O;
        } else if (type_str == "write" || type_str == "Data_Write") {
            type = dr_W;
        } else if (type_str == "read" || type_str == "Data_Read") {
            type = dr_R;
        } else if (type_str == "text" || type_str == "Data_Text") {
            type = dr_T;
        } else if (type_str == "informational" || type_str == "Data_Informational") {
            type = dr_I;
        } else {
            throw std::runtime_error("Invalid data xref type: " + type_str + ". Valid types: offset, write, read, text, informational");
        }

        bool success = add_dref(from, to, type);

        return json{
            {"success", success},
            {"from", format_ea(from)},
            {"to", format_ea(to)},
            {"xref_type", type_str}
        };
    }

    // Delete a code cross-reference
    static json delete_code_xref(const json& params) {
        ea_t from = parse_ea(params["from"]).value();
        ea_t to = parse_ea(params["to"]).value();
        bool expand = params.value("expand", false);

        bool success = del_cref(from, to, expand);

        return json{
            {"success", success},
            {"from", format_ea(from)},
            {"to", format_ea(to)},
            {"expand", expand}
        };
    }

    // Delete a data cross-reference
    static json delete_data_xref(const json& params) {
        ea_t from = parse_ea(params["from"]).value();
        ea_t to = parse_ea(params["to"]).value();

        del_dref(from, to);

        return json{
            {"success", true},
            {"from", format_ea(from)},
            {"to", format_ea(to)}
        };
    }

    // Delete all xrefs from an address
    static json delete_all_xrefs(const json& params) {
        ea_t ea = parse_ea(params["address"]).value();
        bool expand = params.value("expand", false);

        delete_all_xrefs_from(ea, expand);

        return json{
            {"success", true},
            {"address", format_ea(ea)},
            {"expand", expand}
        };
    }
    */

    // Get only data xrefs to an address
    static json get_data_xrefs_to(const json &params) {
        auto ea_opt = parse_ea(params["address"]);
        if (!ea_opt.has_value()) {
            throw std::runtime_error("Invalid address format");
        }
        ea_t ea = ea_opt.value();

        json xrefs = json::array();

        for (ea_t from = get_first_dref_to(ea); from != BADADDR; from = get_next_dref_to(ea, from)) {
            xrefblk_t xb;
            // Find the specific xref to get its type
            for (bool ok = xb.first_to(ea, XREF_DATA); ok; ok = xb.next_to()) {
                if (xb.from == from && !xb.iscode) {
                    xrefs.push_back(build_xref_json(xb));
                    break;
                }
            }
        }

        return json{
            {"address", format_ea(ea)},
            {"xref_count", xrefs.size()},
            {"xrefs", xrefs}
        };
    }

    // Get only data xrefs from an address
    static json get_data_xrefs_from(const json &params) {
        auto ea_opt = parse_ea(params["address"]);
        if (!ea_opt.has_value()) {
            throw std::runtime_error("Invalid address format");
        }
        ea_t ea = ea_opt.value();

        json xrefs = json::array();

        for (ea_t to = get_first_dref_from(ea); to != BADADDR; to = get_next_dref_from(ea, to)) {
            xrefblk_t xb;
            // Find the specific xref to get its type
            for (bool ok = xb.first_from(ea, XREF_DATA); ok; ok = xb.next_from()) {
                if (xb.to == to && !xb.iscode) {
                    xrefs.push_back(build_xref_json(xb));
                    break;
                }
            }
        }

        return json{
            {"address", format_ea(ea)},
            {"xref_count", xrefs.size()},
            {"xrefs", xrefs}
        };
    }

    // Get only code xrefs to an address
    static json get_code_xrefs_to(const json &params) {
        auto ea_opt = parse_ea(params["address"]);
        if (!ea_opt.has_value()) {
            throw std::runtime_error("Invalid address format");
        }
        ea_t ea = ea_opt.value();
        bool include_flow = params.value("include_flow", false);

        json xrefs = json::array();

        for (ea_t from = include_flow ? get_first_cref_to(ea) : get_first_fcref_to(ea);
             from != BADADDR;
             from = include_flow ? get_next_cref_to(ea, from) : get_next_fcref_to(ea, from)) {
            xrefblk_t xb;
            // Find the specific xref to get its type
            int flags = include_flow ? XREF_ALL : XREF_FAR;
            for (bool ok = xb.first_to(ea, flags); ok; ok = xb.next_to()) {
                if (xb.from == from && xb.iscode) {
                    xrefs.push_back(build_xref_json(xb));
                    break;
                }
            }
        }

        return json{
            {"address", format_ea(ea)},
            {"xref_count", xrefs.size()},
            {"include_flow", include_flow},
            {"xrefs", xrefs}
        };
    }

    // Get only code xrefs from an address
    static json get_code_xrefs_from(const json &params) {
        auto ea_opt = parse_ea(params["address"]);
        if (!ea_opt.has_value()) {
            throw std::runtime_error("Invalid address format");
        }
        ea_t ea = ea_opt.value();
        bool include_flow = params.value("include_flow", false);

        json xrefs = json::array();

        for (ea_t to = include_flow ? get_first_cref_from(ea) : get_first_fcref_from(ea);
             to != BADADDR;
             to = include_flow ? get_next_cref_from(ea, to) : get_next_fcref_from(ea, to)) {
            xrefblk_t xb;
            // Find the specific xref to get its type
            int flags = include_flow ? XREF_ALL : XREF_FAR;
            for (bool ok = xb.first_from(ea, flags); ok; ok = xb.next_from()) {
                if (xb.to == to && xb.iscode) {
                    xrefs.push_back(build_xref_json(xb));
                    break;
                }
            }
        }

        return json{
            {"address", format_ea(ea)},
            {"xref_count", xrefs.size()},
            {"include_flow", include_flow},
            {"xrefs", xrefs}
        };
    }

    void register_tools(mcp::McpServer &server) {
        // get_xrefs_to tool
        {
            mcp::ToolDefinition def;
            def.name = "get_xrefs_to";
            def.description = "Get incoming xrefs with type info";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "address", {
                                {"type", "string"},
                                {"description", "Hex address"}
                            }
                        },
                        {
                            "include_flow", {
                                {"type", "boolean"},
                                {"description", "Include flow xrefs"},
                                {"default", false}
                            }
                        }
                    }
                },
                {"required", json::array({"address"})}
            };
            server.register_tool(def, get_xrefs_to);
        }

        // get_xrefs_from tool
        {
            mcp::ToolDefinition def;
            def.name = "get_xrefs_from";
            def.description = "Get outgoing xrefs with type info";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "address", {
                                {"type", "string"},
                                {"description", "Hex address"}
                            }
                        },
                        {
                            "include_flow", {
                                {"type", "boolean"},
                                {"description", "Include flow xrefs"},
                                {"default", false}
                            }
                        }
                    }
                },
                {"required", json::array({"address"})}
            };
            server.register_tool(def, get_xrefs_from);
        }

        // get_data_xrefs_to tool
        {
            mcp::ToolDefinition def;
            def.name = "get_data_xrefs_to";
            def.description = "Get incoming data xrefs only";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "address", {
                                {"type", "string"},
                                {"description", "Hex address"}
                            }
                        }
                    }
                },
                {"required", json::array({"address"})}
            };
            server.register_tool(def, get_data_xrefs_to);
        }

        // get_data_xrefs_from tool
        {
            mcp::ToolDefinition def;
            def.name = "get_data_xrefs_from";
            def.description = "Get outgoing data xrefs only";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "address", {
                                {"type", "string"},
                                {"description", "Hex address"}
                            }
                        }
                    }
                },
                {"required", json::array({"address"})}
            };
            server.register_tool(def, get_data_xrefs_from);
        }

        // get_code_xrefs_to tool
        {
            mcp::ToolDefinition def;
            def.name = "get_code_xrefs_to";
            def.description = "Get incoming code xrefs only";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "address", {
                                {"type", "string"},
                                {"description", "Hex address"}
                            }
                        },
                        {
                            "include_flow", {
                                {"type", "boolean"},
                                {"description", "Include flow xrefs"},
                                {"default", false}
                            }
                        }
                    }
                },
                {"required", json::array({"address"})}
            };
            server.register_tool(def, get_code_xrefs_to);
        }

        // get_code_xrefs_from tool
        {
            mcp::ToolDefinition def;
            def.name = "get_code_xrefs_from";
            def.description = "Get outgoing code xrefs only";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "address", {
                                {"type", "string"},
                                {"description", "Hex address"}
                            }
                        },
                        {
                            "include_flow", {
                                {"type", "boolean"},
                                {"description", "Include flow xrefs"},
                                {"default", false}
                            }
                        }
                    }
                },
                {"required", json::array({"address"})}
            };
            server.register_tool(def, get_code_xrefs_from);
        }

        // Xref manipulation tools commented out - potentially destructive operations
        // Uncomment if you need to modify the IDA database programmatically

        /*
        // add_code_xref tool
        {
            mcp::ToolDefinition def;
            def.name = "add_code_xref";
            def.description = "Add a code cross-reference between two addresses. Creates a call or jump reference. Useful for manual analysis when IDA misses references.";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"from", {
                        {"type", "string"},
                        {"description", "Source address in hex format (e.g., \"0x401000\")"}
                    }},
                    {"to", {
                        {"type", "string"},
                        {"description", "Target address in hex format (e.g., \"0x402000\")"}
                    }},
                    {"xref_type", {
                        {"type", "string"},
                        {"description", "Xref type: call_near, call_far, jump_near, jump_far, flow"},
                        {"enum", json::array({"call_near", "call_far", "jump_near", "jump_far", "flow"})}
                    }}
                }},
                {"required", json::array({"from", "to", "xref_type"})}
            };
            server.register_tool(def, add_code_xref);
        }

        // add_data_xref tool
        {
            mcp::ToolDefinition def;
            def.name = "add_data_xref";
            def.description = "Add a data cross-reference between two addresses. Creates read, write, offset, or informational reference. Useful for documenting data dependencies.";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"from", {
                        {"type", "string"},
                        {"description", "Source address in hex format (e.g., \"0x401000\")"}
                    }},
                    {"to", {
                        {"type", "string"},
                        {"description", "Target address in hex format (e.g., \"0x404000\")"}
                    }},
                    {"xref_type", {
                        {"type", "string"},
                        {"description", "Xref type: offset, write, read, text, informational"},
                        {"enum", json::array({"offset", "write", "read", "text", "informational"})}
                    }}
                }},
                {"required", json::array({"from", "to", "xref_type"})}
            };
            server.register_tool(def, add_data_xref);
        }

        // delete_code_xref tool
        {
            mcp::ToolDefinition def;
            def.name = "delete_code_xref";
            def.description = "Delete a code cross-reference between two addresses. Use expand=true to delete all xrefs in a range.";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"from", {
                        {"type", "string"},
                        {"description", "Source address in hex format (e.g., \"0x401000\")"}
                    }},
                    {"to", {
                        {"type", "string"},
                        {"description", "Target address in hex format (e.g., \"0x402000\")"}
                    }},
                    {"expand", {
                        {"type", "boolean"},
                        {"description", "Expand range deletion"},
                        {"default", false}
                    }}
                }},
                {"required", json::array({"from", "to"})}
            };
            server.register_tool(def, delete_code_xref);
        }

        // delete_data_xref tool
        {
            mcp::ToolDefinition def;
            def.name = "delete_data_xref";
            def.description = "Delete a data cross-reference between two addresses.";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"from", {
                        {"type", "string"},
                        {"description", "Source address in hex format (e.g., \"0x401000\")"}
                    }},
                    {"to", {
                        {"type", "string"},
                        {"description", "Target address in hex format (e.g., \"0x404000\")"}
                    }}
                }},
                {"required", json::array({"from", "to"})}
            };
            server.register_tool(def, delete_data_xref);
        }

        // delete_all_xrefs_from tool
        {
            mcp::ToolDefinition def;
            def.name = "delete_all_xrefs_from";
            def.description = "Delete ALL cross-references (both code and data) from a specific address. Use with caution!";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"address", {
                        {"type", "string"},
                        {"description", "Address in hex format (e.g., \"0x401000\")"}
                    }},
                    {"expand", {
                        {"type", "boolean"},
                        {"description", "Expand range deletion"},
                        {"default", false}
                    }}
                }},
                {"required", json::array({"address"})}
            };
            server.register_tool(def, delete_all_xrefs);
        }
        */
    }
} // namespace ida_mcp::tools::xrefs
