#include "tools/tools.hpp"
#include <lines.hpp>

namespace ida_mcp::tools::comments {
    namespace {
        // Anonymous namespace - internal linkage

        // Get comment at a specific address
        json handle_get_cmt(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();
            bool repeatable = params.value("repeatable", false);

            qstring comment;
            get_cmt(&comment, ea, repeatable);

            return json{
                {"address", format_ea(ea)},
                {"comment", comment.empty() ? nullptr : json(comment.c_str())},
                {"repeatable", repeatable}
            };
        }

        // Set comment at a specific address
        json handle_set_cmt(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();
            std::string comment = params["comment"];
            bool repeatable = params.value("repeatable", false);

            bool success = set_cmt(ea, comment.c_str(), repeatable);

            return json{
                {"address", format_ea(ea)},
                {"comment", comment},
                {"repeatable", repeatable},
                {"success", success}
            };
        }

        // Get function comment
        static json get_func_cmt(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();
            bool repeatable = params.value("repeatable", false);

            func_t *func = get_func(ea);
            if (func == nullptr) {
                throw std::runtime_error("Address " + format_ea(ea) + " is not within a function");
            }

            // Get function name
            qstring name;
            std::string name_str;
            if (get_func_name(&name, func->start_ea) > 0) {
                name_str = name.c_str();
            } else {
                char buf[32];
                qsnprintf(buf, sizeof(buf), "sub_%llX", (uint64) func->start_ea);
                name_str = buf;
            }

            // Get comment at function start
            qstring comment;
            get_cmt(&comment, func->start_ea, repeatable);

            return json{
                {"query_address", format_ea(ea)},
                {"function_name", name_str},
                {"function_start", format_ea(func->start_ea)},
                {"comment", comment.empty() ? nullptr : json(comment.c_str())},
                {"repeatable", repeatable}
            };
        }

        // Set function comment
        static json set_func_cmt(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();
            std::string comment = params["comment"];
            bool repeatable = params.value("repeatable", false);

            func_t *func = get_func(ea);
            if (func == nullptr) {
                throw std::runtime_error("Address " + format_ea(ea) + " is not within a function");
            }

            // Get function name
            qstring name;
            std::string name_str;
            if (get_func_name(&name, func->start_ea) > 0) {
                name_str = name.c_str();
            } else {
                char buf[32];
                qsnprintf(buf, sizeof(buf), "sub_%llX", (uint64) func->start_ea);
                name_str = buf;
            }

            // Set comment at function start
            bool success = set_cmt(func->start_ea, comment.c_str(), repeatable);

            return json{
                {"query_address", format_ea(ea)},
                {"function_name", name_str},
                {"function_start", format_ea(func->start_ea)},
                {"comment", comment},
                {"repeatable", repeatable},
                {"success", success}
            };
        }
    } // anonymous namespace

    void register_tools(mcp::McpServer &server) {
        // get_cmt tool
        {
            mcp::ToolDefinition def;
            def.name = "get_cmt";
            def.description = "Get comment at address";
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
                            "repeatable", {
                                {"type", "boolean"},
                                {"description", "Get repeatable"},
                                {"default", false}
                            }
                        }
                    }
                },
                {"required", json::array({"address"})}
            };
            server.register_tool(def, handle_get_cmt);
        }

        // set_cmt tool
        {
            mcp::ToolDefinition def;
            def.name = "set_cmt";
            def.description = "Set comment at address";
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
                            "comment", {
                                {"type", "string"},
                                {"description", "Comment text"}
                            }
                        },
                        {
                            "repeatable", {
                                {"type", "boolean"},
                                {"description", "Set repeatable"},
                                {"default", false}
                            }
                        }
                    }
                },
                {"required", json::array({"address", "comment"})}
            };
            server.register_tool(def, handle_set_cmt);
        }

        // get_func_cmt tool
        {
            mcp::ToolDefinition def;
            def.name = "get_func_cmt";
            def.description = "Get function comment";
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
                            "repeatable", {
                                {"type", "boolean"},
                                {"description", "Get repeatable"},
                                {"default", false}
                            }
                        }
                    }
                },
                {"required", json::array({"address"})}
            };
            server.register_tool(def, get_func_cmt);
        }

        // set_func_cmt tool
        {
            mcp::ToolDefinition def;
            def.name = "set_func_cmt";
            def.description = "Set function comment";
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
                            "comment", {
                                {"type", "string"},
                                {"description", "Comment text"}
                            }
                        },
                        {
                            "repeatable", {
                                {"type", "boolean"},
                                {"description", "Set repeatable"},
                                {"default", false}
                            }
                        }
                    }
                },
                {"required", json::array({"address", "comment"})}
            };
            server.register_tool(def, set_func_cmt);
        }
    }
} // namespace ida_mcp::tools::comments
