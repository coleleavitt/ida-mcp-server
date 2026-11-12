#include "tools/tools.hpp"
#include <typeinf.hpp>

namespace ida_mcp::tools::decl_compiler {
    namespace {
        json parse_decl_impl(const json &params) {
            std::string decl = params["declaration"].get<std::string>();

            int pt_flags = PT_SIL | PT_TYP | PT_VAR | PT_HIGH;
            if (params.contains("silent") && !params["silent"].get<bool>()) {
                pt_flags &= ~PT_SIL;
            }

            tinfo_t tif;
            qstring name;
            bool ok = ::parse_decl(&tif, &name, nullptr, decl.c_str(), pt_flags);

            if (!ok) {
                throw std::runtime_error("Failed to parse declaration: " + decl);
            }

            qstring type_str;
            tif.print(&type_str);

            json result = {
                {"success", true},
                {"declaration", decl},
                {"parsed_type", type_str.c_str()}
            };

            if (!name.empty()) {
                result["name"] = name.c_str();
            }

            result["size"] = static_cast<uint64_t>(tif.get_size());
            result["is_ptr"] = tif.is_ptr();
            result["is_func"] = tif.is_func();
            result["is_struct"] = tif.is_struct();
            result["is_union"] = tif.is_union();
            result["is_enum"] = tif.is_enum();
            result["is_array"] = tif.is_array();
            result["is_floating"] = tif.is_floating();

            return result;
        }

        json parse_decls_impl(const json &params) {
            std::string input = params["declarations"].get<std::string>();

            int hti_flags = HTI_HIGH | HTI_DCL;
            if (params.contains("pack_alignment") && !params["pack_alignment"].is_null()) {
                int pack = params["pack_alignment"].get<int>();
                hti_flags |= (pack << HTI_PAK_SHIFT) & HTI_PAK;
            }

            int errors = ::parse_decls(get_idati(), input.c_str(), nullptr, hti_flags);

            return json{
                {"success", errors == 0},
                {"error_count", errors},
                {"input_length", input.size()}
            };
        }

        json apply_type_at_address_impl(const json &params) {
            std::string decl = params["declaration"].get<std::string>();
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            tinfo_t tif;
            qstring name;
            bool parsed = ::parse_decl(&tif, &name, nullptr, decl.c_str(),
                                       PT_SIL | PT_TYP | PT_VAR | PT_HIGH);
            if (!parsed) {
                throw std::runtime_error("Failed to parse declaration: " + decl);
            }

            bool applied = apply_tinfo(ea, tif, TINFO_DEFINITE);

            qstring type_str;
            tif.print(&type_str);

            return json{
                {"address", format_ea(ea)},
                {"declaration", decl},
                {"parsed_type", type_str.c_str()},
                {"applied", applied}
            };
        }

        json get_type_at_address_impl(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            qstring out;
            int prtype_flags = PRTYPE_1LINE | PRTYPE_SEMI;
            if (params.contains("multiline") && params["multiline"].get<bool>()) {
                prtype_flags &= ~PRTYPE_1LINE;
            }

            bool ok = ::print_type(&out, ea, prtype_flags);
            if (!ok) {
                throw std::runtime_error("No type information at " + format_ea(ea));
            }

            tinfo_t tif;
            bool has_tinfo = get_tinfo(&tif, ea);

            json result = {
                {"address", format_ea(ea)},
                {"type_string", out.c_str()}
            };

            if (has_tinfo) {
                result["size"] = static_cast<uint64_t>(tif.get_size());
                result["is_ptr"] = tif.is_ptr();
                result["is_func"] = tif.is_func();
                result["is_struct"] = tif.is_struct();
            }

            return result;
        }
    }

    void register_tools(mcp::McpServer &server) { {
            mcp::ToolDefinition def;
            def.name = "parse_c_declaration";
            def.description = "Parse a C type declaration and return type information. "
                    "Examples: 'int *foo', 'struct { int x; int y; }', 'void (*callback)(int, char*)'";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {"declaration", {{"type", "string"}, {"description", "C declaration string"}}},
                        {"silent", {{"type", "boolean"}, {"description", "Suppress error messages (default true)"}}}
                    }
                },
                {"required", json::array({"declaration"})}
            };
            server.register_tool(def, parse_decl_impl);
        } {
            mcp::ToolDefinition def;
            def.name = "parse_c_declarations";
            def.description = "Parse multiple C declarations and store them in the type library. "
                    "Input can be a C header-style string with structs, typedefs, enums, etc.";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {"declarations", {{"type", "string"}, {"description", "C declarations (header-style)"}}},
                        {"pack_alignment", {{"type", "integer"}, {"description", "Pack alignment (optional)"}}}
                    }
                },
                {"required", json::array({"declarations"})}
            };
            server.register_tool(def, parse_decls_impl);
        } {
            mcp::ToolDefinition def;
            def.name = "apply_type_at_address";
            def.description = "Parse a C declaration and apply the resulting type to an address. "
                    "Useful for setting function prototypes or variable types.";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {"address", {{"type", "string"}, {"description", "Hex address"}}},
                        {"declaration", {{"type", "string"}, {"description", "C declaration string"}}}
                    }
                },
                {"required", json::array({"address", "declaration"})}
            };
            server.register_tool(def, apply_type_at_address_impl);
        } {
            mcp::ToolDefinition def;
            def.name = "get_type_at_address";
            def.description = "Get the C type declaration string for the type at an address";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {"address", {{"type", "string"}, {"description", "Hex address"}}},
                        {"multiline", {{"type", "boolean"}, {"description", "Multi-line output (default false)"}}}
                    }
                },
                {"required", json::array({"address"})}
            };
            server.register_tool(def, get_type_at_address_impl);
        }
    }
}
