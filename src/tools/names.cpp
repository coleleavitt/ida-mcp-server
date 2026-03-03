#include "tools/tools.hpp"
#include <name.hpp>

namespace ida_mcp::tools::names {
    namespace {
        // Anonymous namespace - internal linkage

        // Get the name at a specific address
        json handle_get_name(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            qstring name;
            get_ea_name(&name, ea);

            bool is_public = !name.empty() && is_public_name(ea);
            bool is_weak = !name.empty() && is_weak_name(ea);

            return json{
                {"address", format_ea(ea)},
                {"name", name.empty() ? nullptr : json(name.c_str())},
                {"is_public", is_public},
                {"is_weak", is_weak}
            };
        }

        // Set the name at a specific address
        json handle_set_name(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();
            std::string name = params["name"];

            bool success;
            if (name.empty()) {
                // Delete name
                success = del_global_name(ea);
            } else {
                // Set name (SN_NOWARN = don't warn on failure)
                success = set_name(ea, name.c_str(), SN_NOWARN);
            }

            return json{
                {"address", format_ea(ea)},
                {"name", name},
                {"success", success}
            };
        }

        // Get the "true" name (with function naming logic)
        json handle_get_true_name(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            func_t *func = get_func(ea);
            std::string name;
            bool is_function = (func != nullptr);
            bool is_auto_generated = false;

            if (func != nullptr) {
                // Try to get function name
                qstring fname;
                if (get_func_name(&fname, func->start_ea) > 0) {
                    name = fname.c_str();
                } else {
                    char buf[32];
                    qsnprintf(buf, sizeof(buf), "sub_%llX", (uint64) func->start_ea);
                    name = buf;
                    is_auto_generated = true;
                }
            } else {
                // Not a function - try regular name
                qstring regular_name;
                get_ea_name(&regular_name, ea);

                if (regular_name.empty()) {
                    char buf[32];
                    qsnprintf(buf, sizeof(buf), "loc_%llX", (uint64) ea);
                    name = buf;
                    is_auto_generated = true;
                } else {
                    name = regular_name.c_str();
                }
            }

            // Check if name is auto-generated (IDA-generated names)
            if (!is_auto_generated) {
                // IDA generates various auto-names with these prefixes
                is_auto_generated = (name.rfind("sub_", 0) == 0 ||
                                     name.rfind("loc_", 0) == 0 ||
                                     name.rfind("off_", 0) == 0 ||
                                     name.rfind("dword_", 0) == 0 ||
                                     name.rfind("qword_", 0) == 0 ||
                                     name.rfind("word_", 0) == 0 ||
                                     name.rfind("byte_", 0) == 0 ||
                                     name.rfind("unk_", 0) == 0 ||
                                     name.rfind("stru_", 0) == 0 ||
                                     name.rfind("asc_", 0) == 0 ||
                                     name.rfind("flt_", 0) == 0 ||
                                     name.rfind("dbl_", 0) == 0);
            }

            return json{
                {"address", format_ea(ea)},
                {"name", name},
                {"is_function", is_function},
                {"is_auto_generated", is_auto_generated}
            };
        }
    } // anonymous namespace

    void register_tools(mcp::McpServer &server) {
        // get_name tool
        {
            mcp::ToolDefinition def;
            def.name = "get_name";
            def.description = "Get name at address";
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
            server.register_tool(def, handle_get_name);
        }

        // set_name tool
        {
            mcp::ToolDefinition def;
            def.name = "set_name";
            def.description = "Set name at address";
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
                            "name", {
                                {"type", "string"},
                                {"description", "Name to set"}
                            }
                        }
                    }
                },
                {"required", json::array({"address", "name"})}
            };
            server.register_tool(def, handle_set_name);
        }

        // get_true_name tool
        {
            mcp::ToolDefinition def;
            def.name = "get_true_name";
            def.description = "Get true name with naming logic";
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
            server.register_tool(def, handle_get_true_name);
        }
    }
} // namespace ida_mcp::tools::names
