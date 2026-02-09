#include "tools/tools.hpp"
#include <demangle.hpp>
#include <name.hpp>

namespace ida_mcp::tools::demangling {
    namespace {
        json handle_demangle_name(const json &params) {
            std::string mangled_name = params["mangled_name"].get<std::string>();
            uint32_t mask = params.value("mask", 0);

            qstring demangled;
            int result = demangle_name(&demangled, mangled_name.c_str(), mask);

            if (result > 0 && !demangled.empty()) {
                return json{
                    {"mangled_name", mangled_name},
                    {"demangled_name", demangled.c_str()},
                    {"mask", mask}
                };
            } else {
                return json{
                    {"mangled_name", mangled_name},
                    {"demangled_name", nullptr},
                    {"error", "Failed to demangle name (not a valid mangled name or unsupported format)"}
                };
            }
        }

        json handle_demangle_name_long(const json &params) {
            std::string mangled_name = params["mangled_name"].get<std::string>();

            qstring demangled;
            int result = demangle_name(&demangled, mangled_name.c_str(), MNG_LONG_FORM);

            if (result > 0 && !demangled.empty()) {
                return json{
                    {"mangled_name", mangled_name},
                    {"demangled_name", demangled.c_str()},
                    {"form", "long"}
                };
            } else {
                return json{
                    {"mangled_name", mangled_name},
                    {"demangled_name", nullptr},
                    {"error", "Failed to demangle name"}
                };
            }
        }

        json handle_demangle_name_short(const json &params) {
            std::string mangled_name = params["mangled_name"].get<std::string>();

            qstring demangled;
            int result = demangle_name(&demangled, mangled_name.c_str(), MNG_SHORT_FORM);

            if (result > 0 && !demangled.empty()) {
                return json{
                    {"mangled_name", mangled_name},
                    {"demangled_name", demangled.c_str()},
                    {"form", "short"}
                };
            } else {
                return json{
                    {"mangled_name", mangled_name},
                    {"demangled_name", nullptr},
                    {"error", "Failed to demangle name"}
                };
            }
        }

        json handle_demangle_name_at_address(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();
            bool long_form = params.value("long_form", false);

            qstring name;
            get_ea_name(&name, ea);

            if (name.empty()) {
                throw std::runtime_error("No name at " + format_ea(ea));
            }

            qstring demangled;
            int result = demangle_name(&demangled, name.c_str(),
                                       long_form ? MNG_LONG_FORM : MNG_SHORT_FORM);

            if (result > 0 && !demangled.empty()) {
                return json{
                    {"address", format_ea(ea)},
                    {"mangled_name", name.c_str()},
                    {"demangled_name", demangled.c_str()},
                    {"long_form", long_form}
                };
            } else {
                return json{
                    {"address", format_ea(ea)},
                    {"mangled_name", name.c_str()},
                    {"demangled_name", nullptr},
                    {"note", "Name is not mangled or demangling failed"}
                };
            }
        }

        json handle_can_demangle(const json &params) {
            std::string name = params["name"].get<std::string>();

            qstring demangled;
            int result = demangle_name(&demangled, name.c_str(), 0);

            bool can_demangle = (result > 0 && !demangled.empty());

            return json{
                {"name", name},
                {"can_demangle", can_demangle},
                {"demangled_preview", can_demangle ? json(demangled.c_str()) : nullptr}
            };
        }
    } // anonymous namespace

    void register_tools(mcp::McpServer &server) {
        // demangle_name
        {
            mcp::ToolDefinition def;
            def.name = "demangle_name";
            def.description = "Demangle C++ name with options";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "mangled_name", {
                                {"type", "string"},
                                {"description", "Mangled name"}
                            }
                        },
                        {
                            "mask", {
                                {"type", "number"},
                                {"description", "Demangling mask"}
                            }
                        }
                    }
                },
                {"required", json::array({"mangled_name"})}
            };
            server.register_tool(def, handle_demangle_name);
        }

        // demangle_name_long
        {
            mcp::ToolDefinition def;
            def.name = "demangle_name_long";
            def.description = "Demangle C++ name long form";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "mangled_name", {
                                {"type", "string"},
                                {"description", "Mangled name"}
                            }
                        }
                    }
                },
                {"required", json::array({"mangled_name"})}
            };
            server.register_tool(def, handle_demangle_name_long);
        }

        // demangle_name_short
        {
            mcp::ToolDefinition def;
            def.name = "demangle_name_short";
            def.description = "Demangle C++ name short form";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "mangled_name", {
                                {"type", "string"},
                                {"description", "Mangled name"}
                            }
                        }
                    }
                },
                {"required", json::array({"mangled_name"})}
            };
            server.register_tool(def, handle_demangle_name_short);
        }

        // demangle_name_at_address
        {
            mcp::ToolDefinition def;
            def.name = "demangle_name_at_address";
            def.description = "Demangle name at address";
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
                            "long_form", {
                                {"type", "boolean"},
                                {"description", "Use long form"}
                            }
                        }
                    }
                },
                {"required", json::array({"address"})}
            };
            server.register_tool(def, handle_demangle_name_at_address);
        }

        // can_demangle
        {
            mcp::ToolDefinition def;
            def.name = "can_demangle";
            def.description = "Check if name is mangled";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "name", {
                                {"type", "string"},
                                {"description", "Name to check"}
                            }
                        }
                    }
                },
                {"required", json::array({"name"})}
            };
            server.register_tool(def, handle_can_demangle);
        }
    }
} // namespace ida_mcp::tools::demangling
