#include "tools/tools.hpp"
#include <typeinf.hpp>
#include <funcs.hpp>
#include <ida.hpp>

namespace ida_mcp::tools::types {
    namespace {
        json handle_get_type_info(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            tinfo_t tif;
            if (!get_tinfo(&tif, ea)) {
                return json{
                    {"address", format_ea(ea)},
                    {"type_info", nullptr},
                    {"error", "No type information available at this address"}
                };
            }

            qstring type_str;
            tif.print(&type_str);

            return json{
                {"address", format_ea(ea)},
                {"type_info", type_str.c_str()}
            };
        }

        json handle_get_function_tinfo(const json &params) {
            auto func_ea_opt = parse_ea(params["address"]);
            if (!func_ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t func_ea = func_ea_opt.value();

            func_t *func = get_func(func_ea);
            if (func == nullptr) {
                throw std::runtime_error("No function at " + format_ea(func_ea));
            }

            tinfo_t tif;
            if (!get_tinfo(&tif, func->start_ea)) {
                return json{
                    {"address", format_ea(func_ea)},
                    {"has_tinfo", false},
                    {"type", nullptr}
                };
            }

            // Get function details
            func_type_data_t fi;
            if (!tif.get_func_details(&fi)) {
                qstring type_str;
                tif.print(&type_str);

                return json{
                    {"address", format_ea(func_ea)},
                    {"has_tinfo", true},
                    {"type", type_str.c_str()},
                    {"is_function_type", false}
                };
            }

            // Get return type
            qstring ret_type;
            fi.rettype.print(&ret_type);

            // Get arguments
            json args = json::array();
            for (size_t i = 0; i < fi.size(); i++) {
                const funcarg_t &arg = fi[i];

                qstring arg_type;
                arg.type.print(&arg_type);

                json arg_obj;
                arg_obj["name"] = arg.name.c_str();
                arg_obj["type"] = arg_type.c_str();

                args.push_back(arg_obj);
            }

            // Get calling convention via get_cc() method
            callcnv_t cc = fi.get_cc();

            // Format calling convention as hex for now
            char cc_str[32];
            qsnprintf(cc_str, sizeof(cc_str), "0x%x", cc);

            json result;
            result["address"] = format_ea(func_ea);
            result["has_tinfo"] = true;
            result["is_function_type"] = true;
            result["return_type"] = ret_type.c_str();
            result["arguments"] = args;
            result["calling_convention"] = cc_str;
            result["has_varargs"] = fi.is_vararg_cc();
            result["is_noret"] = fi.is_noret();
            result["is_pure"] = fi.is_pure();

            return result;
        }

        json handle_parse_type_declaration(const json &params) {
            std::string declaration = params["declaration"].get<std::string>();

            tinfo_t tif;
            qstring name;

            // Parse the declaration
            if (!parse_decl(&tif, &name, nullptr, declaration.c_str(), PT_SIL)) {
                throw std::runtime_error("Failed to parse type declaration: " + declaration);
            }

            qstring type_str;
            tif.print(&type_str);

            return json{
                {"declaration", declaration},
                {"parsed_type", type_str.c_str()},
                {"name", name.empty() ? nullptr : json(name.c_str())}
            };
        }

        json handle_guess_function_type(const json &params) {
            auto func_ea_opt = parse_ea(params["address"]);
            if (!func_ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t func_ea = func_ea_opt.value();

            func_t *func = get_func(func_ea);
            if (func == nullptr) {
                throw std::runtime_error("No function at " + format_ea(func_ea));
            }

            tinfo_t tif;
            int result = guess_tinfo(&tif, func->start_ea);

            if (result != GUESS_FUNC_OK && result != GUESS_FUNC_TRIVIAL) {
                return json{
                    {"function_address", format_ea(func_ea)},
                    {"guessed_signature", nullptr},
                    {"error", "Failed to guess function type"}
                };
            }

            qstring sig_str;
            tif.print(&sig_str);

            return json{
                {"function_address", format_ea(func_ea)},
                {"guessed_signature", sig_str.c_str()}
            };
        }

        json handle_get_type_size(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            tinfo_t tif;
            if (!get_tinfo(&tif, ea)) {
                return json{
                    {"address", format_ea(ea)},
                    {"type_size", nullptr},
                    {"error", "No type information available"}
                };
            }

            size_t size = tif.get_size();

            return json{
                {"address", format_ea(ea)},
                {"type_size", size == BADSIZE ? nullptr : json(static_cast<uint64_t>(size))}
            };
        }

        // List all enums in the type library
        json handle_list_enums(const json &params) {
            til_t *ti = get_idati();
            if (ti == nullptr) {
                throw std::runtime_error("No type library available");
            }

            int limit = params.value("limit", 1000);
            json enums = json::array();

            // Iterate through all ordinals
            uint32 ord_limit = get_ordinal_limit(ti);
            for (uint32 ord = 1; ord < ord_limit && enums.size() < (size_t)limit; ord++) {
                tinfo_t tif;
                if (tif.get_numbered_type(ti, ord)) {
                    if (tif.is_enum()) {
                        qstring name;
                        if (tif.get_type_name(&name)) {
                            json enum_info = json::object();
                            enum_info["ordinal"] = ord;
                            enum_info["name"] = name.c_str();
                            enum_info["is_bitmask"] = tif.is_bitmask_enum();
                            enum_info["member_count"] = tif.get_enum_nmembers();
                            enum_info["width"] = tif.get_enum_width();

                            size_t size = tif.get_size();
                            if (size != BADSIZE) {
                                enum_info["size"] = size;
                            }

                            enums.push_back(enum_info);
                        }
                    }
                }
            }

            return json{
                {"enum_count", enums.size()},
                {"enums", enums},
                {"truncated", enums.size() >= (size_t)limit}
            };
        }

        // Get enum details including all members
        json handle_get_enum_members(const json &params) {
            if (!params.contains("name") || !params["name"].is_string()) {
                throw std::runtime_error("Missing required parameter: name");
            }

            std::string enum_name = params["name"];
            til_t *ti = get_idati();
            if (ti == nullptr) {
                throw std::runtime_error("No type library available");
            }

            tinfo_t tif;
            if (!tif.get_named_type(ti, enum_name.c_str())) {
                throw std::runtime_error("Enum '" + enum_name + "' not found");
            }

            if (!tif.is_enum()) {
                throw std::runtime_error("'" + enum_name + "' is not an enum");
            }

            enum_type_data_t etd;
            if (!tif.get_enum_details(&etd)) {
                throw std::runtime_error("Failed to get enum details for '" + enum_name + "'");
            }

            json members = json::array();
            for (size_t i = 0; i < etd.size(); i++) {
                const edm_t &member = etd[i];
                json member_info = json::object();
                member_info["name"] = member.name.c_str();
                member_info["value"] = member.value;

                if (!member.cmt.empty()) {
                    member_info["comment"] = member.cmt.c_str();
                }

                members.push_back(member_info);
            }

            return json{
                {"name", enum_name},
                {"is_bitmask", tif.is_bitmask_enum()},
                {"width", tif.get_enum_width()},
                {"size", tif.get_size()},
                {"radix", tif.get_enum_radix()},
                {"member_count", members.size()},
                {"members", members}
            };
        }

        // List all structs/unions in the type library
        json handle_list_structs(const json &params) {
            til_t *ti = get_idati();
            if (ti == nullptr) {
                throw std::runtime_error("No type library available");
            }

            int limit = params.value("limit", 1000);
            json structs = json::array();

            uint32 ord_limit = get_ordinal_limit(ti);
            for (uint32 ord = 1; ord < ord_limit && structs.size() < (size_t)limit; ord++) {
                tinfo_t tif;
                if (tif.get_numbered_type(ti, ord)) {
                    if (tif.is_udt()) {
                        qstring name;
                        if (tif.get_type_name(&name)) {
                            json struct_info = json::object();
                            struct_info["ordinal"] = ord;
                            struct_info["name"] = name.c_str();
                            struct_info["is_union"] = tif.is_union();
                            struct_info["member_count"] = tif.get_udt_nmembers();

                            size_t size = tif.get_size();
                            if (size != BADSIZE) {
                                struct_info["size"] = size;
                            }

                            structs.push_back(struct_info);
                        }
                    }
                }
            }

            return json{
                {"struct_count", structs.size()},
                {"structs", structs},
                {"truncated", structs.size() >= (size_t)limit}
            };
        }

        // Get struct/union details including all members
        json handle_get_struct_members(const json &params) {
            if (!params.contains("name") || !params["name"].is_string()) {
                throw std::runtime_error("Missing required parameter: name");
            }

            std::string struct_name = params["name"];
            til_t *ti = get_idati();
            if (ti == nullptr) {
                throw std::runtime_error("No type library available");
            }

            tinfo_t tif;
            if (!tif.get_named_type(ti, struct_name.c_str())) {
                throw std::runtime_error("Struct '" + struct_name + "' not found");
            }

            if (!tif.is_udt()) {
                throw std::runtime_error("'" + struct_name + "' is not a struct or union");
            }

            udt_type_data_t udt;
            if (!tif.get_udt_details(&udt)) {
                throw std::runtime_error("Failed to get struct details for '" + struct_name + "'");
            }

            json members = json::array();
            for (size_t i = 0; i < udt.size(); i++) {
                const udm_t &member = udt[i];
                json member_info = json::object();
                member_info["name"] = member.name.c_str();
                member_info["offset"] = static_cast<uint64_t>(member.offset / 8);
                member_info["size"] = static_cast<uint64_t>(member.size / 8);

                qstring type_str;
                member.type.print(&type_str);
                member_info["type"] = type_str.c_str();

                if (!member.cmt.empty()) {
                    member_info["comment"] = member.cmt.c_str();
                }

                // Check if array
                if (member.type.is_array()) {
                    array_type_data_t atd;
                    if (member.type.get_array_details(&atd)) {
                        json array_info = json::object();
                        array_info["is_array"] = true;
                        array_info["element_count"] = atd.nelems;

                        qstring elem_type;
                        atd.elem_type.print(&elem_type);
                        array_info["element_type"] = elem_type.c_str();

                        size_t elem_size = atd.elem_type.get_size();
                        if (elem_size != BADSIZE) {
                            array_info["element_size"] = elem_size;
                        }

                        member_info["array"] = array_info;
                    }
                }

                members.push_back(member_info);
            }

            return json{
                {"name", struct_name},
                {"is_union", tif.is_union()},
                {"size", tif.get_size()},
                {"member_count", members.size()},
                {"members", members}
            };
        }

        // Get array information from a type
        json handle_get_array_info(const json &params) {
            if (!params.contains("name") || !params["name"].is_string()) {
                throw std::runtime_error("Missing required parameter: name");
            }

            std::string type_name = params["name"];
            til_t *ti = get_idati();
            if (ti == nullptr) {
                throw std::runtime_error("No type library available");
            }

            tinfo_t tif;
            if (!tif.get_named_type(ti, type_name.c_str())) {
                throw std::runtime_error("Type '" + type_name + "' not found");
            }

            if (!tif.is_array()) {
                throw std::runtime_error("'" + type_name + "' is not an array type");
            }

            array_type_data_t atd;
            if (!tif.get_array_details(&atd)) {
                throw std::runtime_error("Failed to get array details for '" + type_name + "'");
            }

            qstring elem_type_str;
            atd.elem_type.print(&elem_type_str);

            size_t elem_size = atd.elem_type.get_size();
            size_t total_size = tif.get_size();

            return json{
                {"name", type_name},
                {"element_count", atd.nelems},
                {"element_type", elem_type_str.c_str()},
                {"element_size", elem_size},
                {"total_size", total_size},
                {"base", atd.base}
            };
        }
        // Describe a type library ordinal (IDA 9.3+)
        // Signature from decompiled libida.so @ 0x55f7b0:
        //   describe_tlc_ordinal(qstring *out, til_t *ti, uint32 ordinal,
        //                        ???, ???, ???, char flags)
        // We only need the first 3 params — the rest default to 0/nullptr.
        struct tlc_desc_result_t {
            qstring desc;
            char pad[82];
        };

        extern "C" int64 describe_tlc_ordinal(
            tlc_desc_result_t *out,
            til_t *ti,
            uint32 ordinal,
            int64 a4,
            int64 a5,
            int64 a6,
            char a7);

        json handle_describe_tlc_ordinal(const json &params) {
            if (!params.contains("ordinal")) {
                return json{{"error", "Missing required parameter: ordinal"}};
            }

            uint32 ordinal = params["ordinal"].get<uint32>();
            til_t *ti = get_idati();
            if (ti == nullptr) {
                return json{{"error", "No type library available"}};
            }

            uint32 ord_limit = get_ordinal_limit(ti);
            if (ordinal == 0 || ordinal >= ord_limit) {
                return json{
                    {"error", "Ordinal out of range"},
                    {"ordinal", ordinal},
                    {"ordinal_limit", ord_limit}
                };
            }

            tlc_desc_result_t result;
            memset(&result, 0, sizeof(result));
            describe_tlc_ordinal(&result, ti, ordinal, 0, 0, 0, 0);

            tinfo_t tif;
            json type_kind = nullptr;
            if (tif.get_numbered_type(ti, ordinal)) {
                if (tif.is_struct()) type_kind = "struct";
                else if (tif.is_union()) type_kind = "union";
                else if (tif.is_enum()) type_kind = "enum";
                else if (tif.is_func()) type_kind = "function";
                else if (tif.is_ptr()) type_kind = "pointer";
                else if (tif.is_array()) type_kind = "array";
                else if (tif.is_typedef()) type_kind = "typedef";
                else type_kind = "other";
            }

            return json{
                {"ordinal", ordinal},
                {"description", result.desc.empty() ? "" : result.desc.c_str()},
                {"type_kind", type_kind},
                {"ordinal_limit", ord_limit}
            };
        }

        json handle_describe_tlc_ordinals_range(const json &params) {
            til_t *ti = get_idati();
            if (ti == nullptr) {
                return json{{"error", "No type library available"}};
            }

            uint32 ord_limit = get_ordinal_limit(ti);
            uint32 start = params.value("start", static_cast<uint32>(1));
            uint32 count = params.value("count", static_cast<uint32>(100));
            if (start == 0) start = 1;
            if (count > 10000) count = 10000;

            json entries = json::array();
            for (uint32 ord = start; ord < ord_limit && entries.size() < count; ord++) {
                tlc_desc_result_t result;
                memset(&result, 0, sizeof(result));
                describe_tlc_ordinal(&result, ti, ord, 0, 0, 0, 0);

                if (result.desc.empty()) continue;

                tinfo_t tif;
                json type_kind = nullptr;
                if (tif.get_numbered_type(ti, ord)) {
                    if (tif.is_struct()) type_kind = "struct";
                    else if (tif.is_union()) type_kind = "union";
                    else if (tif.is_enum()) type_kind = "enum";
                    else if (tif.is_func()) type_kind = "function";
                    else if (tif.is_ptr()) type_kind = "pointer";
                    else if (tif.is_array()) type_kind = "array";
                    else if (tif.is_typedef()) type_kind = "typedef";
                    else type_kind = "other";
                }

                entries.push_back(json{
                    {"ordinal", ord},
                    {"description", result.desc.c_str()},
                    {"type_kind", type_kind}
                });
            }

            return json{
                {"ordinal_limit", ord_limit},
                {"start", start},
                {"returned", entries.size()},
                {"entries", entries}
            };
        }

    } // anonymous namespace

    void register_tools(mcp::McpServer &server) {
        // get_type_info
        {
            mcp::ToolDefinition def;
            def.name = "get_type_info";
            def.description = "Get type info at address";
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
            server.register_tool(def, handle_get_type_info);
        }

        // get_function_tinfo
        {
            mcp::ToolDefinition def;
            def.name = "get_function_tinfo";
            def.description = "Get function type info";
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
            server.register_tool(def, handle_get_function_tinfo);
        }

        // parse_type_declaration
        {
            mcp::ToolDefinition def;
            def.name = "parse_type_declaration";
            def.description = "Parse C type declaration";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "declaration", {
                                {"type", "string"},
                                {"description", "C type string"}
                            }
                        }
                    }
                },
                {"required", json::array({"declaration"})}
            };
            server.register_tool(def, handle_parse_type_declaration);
        }

        // guess_function_type
        {
            mcp::ToolDefinition def;
            def.name = "guess_function_type";
            def.description = "Guess function signature";
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
            server.register_tool(def, handle_guess_function_type);
        }

        // get_type_size
        {
            mcp::ToolDefinition def;
            def.name = "get_type_size";
            def.description = "Get type size in bytes";
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
            server.register_tool(def, handle_get_type_size);
        }

        // list_enums
        {
            mcp::ToolDefinition def;
            def.name = "list_enums";
            def.description = "List all enum types";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "limit", {
                                {"type", "integer"},
                                {"description", "Max results"},
                                {"default", 1000}
                            }
                        }
                    }
                }
            };
            server.register_tool(def, handle_list_enums);
        }

        // get_enum_members
        {
            mcp::ToolDefinition def;
            def.name = "get_enum_members";
            def.description = "Get enum members and values";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "name", {
                                {"type", "string"},
                                {"description", "Enum name"}
                            }
                        }
                    }
                },
                {"required", json::array({"name"})}
            };
            server.register_tool(def, handle_get_enum_members);
        }

        // list_structs
        {
            mcp::ToolDefinition def;
            def.name = "list_structs";
            def.description = "List all struct/union types";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "limit", {
                                {"type", "integer"},
                                {"description", "Max results"},
                                {"default", 1000}
                            }
                        }
                    }
                }
            };
            server.register_tool(def, handle_list_structs);
        }

        // get_struct_members
        {
            mcp::ToolDefinition def;
            def.name = "get_struct_members";
            def.description = "Get struct/union members";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "name", {
                                {"type", "string"},
                                {"description", "Struct name"}
                            }
                        }
                    }
                },
                {"required", json::array({"name"})}
            };
            server.register_tool(def, handle_get_struct_members);
        }

        // get_array_info
        {
            mcp::ToolDefinition def;
            def.name = "get_array_info";
            def.description = "Get array type details";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "name", {
                                {"type", "string"},
                                {"description", "Array type name"}
                            }
                        }
                    }
                },
                {"required", json::array({"name"})}
            };
            server.register_tool(def, handle_get_array_info);
        }
    }
} // namespace ida_mcp::tools::types
