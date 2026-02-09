#include "tools/tools.hpp"
#include <problems.hpp>

namespace ida_mcp::tools::problems {
    namespace {
        json handle_list_all_problems(const json &params) {
            json problems = json::array();

            // Iterate through all problem types
            for (problist_id_t type = 1; type < PR_END; type++) {
                ea_t ea = inf_get_min_ea();

                while (true) {
                    ea = get_problem(type, ea);
                    if (ea == BADADDR) {
                        break;
                    }

                    qstring desc;
                    get_problem_desc(&desc, type, ea);

                    json problem_obj;
                    problem_obj["address"] = format_ea(ea);
                    problem_obj["type"] = static_cast<int>(type);
                    problem_obj["type_name"] = get_problem_name(type, true);
                    problem_obj["description"] = desc.c_str();

                    problems.push_back(problem_obj);

                    ea = next_addr(ea);
                }
            }

            return json{
                {"problem_count", problems.size()},
                {"problems", problems}
            };
        }

        json handle_list_problems_by_type(const json &params) {
            uint8_t problem_type = params["problem_type"].get<uint8_t>();

            if (problem_type == 0 || problem_type >= PR_END) {
                throw std::runtime_error("Problem type must be between 1 and 16");
            }

            // Get optional start/end addresses
            ea_t start_ea = inf_get_min_ea();
            ea_t end_ea = inf_get_max_ea();

            if (params.contains("start_address") && !params["start_address"].is_null()) {
                auto addr = parse_ea(params["start_address"]);
                if (addr.has_value()) {
                    start_ea = addr.value();
                }
            }

            if (params.contains("end_address") && !params["end_address"].is_null()) {
                auto addr = parse_ea(params["end_address"]);
                if (addr.has_value()) {
                    end_ea = addr.value();
                }
            }

            json problems = json::array();
            ea_t ea = start_ea;

            while (ea < end_ea) {
                ea = get_problem(problem_type, ea);
                if (ea == BADADDR || ea >= end_ea) {
                    break;
                }

                qstring desc;
                get_problem_desc(&desc, problem_type, ea);

                json problem_obj;
                problem_obj["address"] = format_ea(ea);
                problem_obj["type"] = static_cast<int>(problem_type);
                problem_obj["type_name"] = get_problem_name(problem_type, true);
                problem_obj["description"] = desc.c_str();

                problems.push_back(problem_obj);

                ea = next_addr(ea);
            }

            return json{
                {"problem_type", static_cast<int>(problem_type)},
                {"problem_type_name", get_problem_name(problem_type, true)},
                {"start_address", format_ea(start_ea)},
                {"end_address", format_ea(end_ea)},
                {"problem_count", problems.size()},
                {"problems", problems}
            };
        }

        json handle_get_problems_at_address(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            json problems = json::array();

            // Check all problem types at this address
            for (problist_id_t type = 1; type < PR_END; type++) {
                if (is_problem_present(type, ea)) {
                    qstring desc;
                    get_problem_desc(&desc, type, ea);

                    json problem_obj;
                    problem_obj["type"] = static_cast<int>(type);
                    problem_obj["type_name"] = get_problem_name(type, true);
                    problem_obj["description"] = desc.c_str();

                    problems.push_back(problem_obj);
                }
            }

            return json{
                {"address", format_ea(ea)},
                {"problem_count", problems.size()},
                {"problems", problems}
            };
        }

        json handle_get_problem_type_name(const json &params) {
            uint8_t problem_type = params["problem_type"].get<uint8_t>();

            if (problem_type == 0 || problem_type >= PR_END) {
                throw std::runtime_error("Problem type must be between 1 and 16");
            }

            bool long_name = params.contains("long_name") && !params["long_name"].is_null()
                                 ? params["long_name"].get<bool>()
                                 : true;

            const char *name = get_problem_name(problem_type, long_name);

            return json{
                {"problem_type", static_cast<int>(problem_type)},
                {"long_name", long_name},
                {"description", name}
            };
        }

        json handle_check_problem_exists(const json &params) {
            uint8_t problem_type = params["problem_type"].get<uint8_t>();
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            if (problem_type == 0 || problem_type >= PR_END) {
                throw std::runtime_error("Problem type must be between 1 and 16");
            }

            bool exists = is_problem_present(problem_type, ea);

            qstring desc;
            if (exists) {
                get_problem_desc(&desc, problem_type, ea);
            }

            return json{
                {"address", format_ea(ea)},
                {"problem_type", static_cast<int>(problem_type)},
                {"problem_type_name", get_problem_name(problem_type, true)},
                {"exists", exists},
                {"description", exists ? desc.c_str() : ""}
            };
        }
    } // anonymous namespace

    void register_tools(mcp::McpServer &server) {
        // list_all_problems
        {
            mcp::ToolDefinition def;
            def.name = "list_all_problems";
            def.description = "List all analysis problems";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {}}
            };
            server.register_tool(def, handle_list_all_problems);
        }

        // list_problems_by_type
        {
            mcp::ToolDefinition def;
            def.name = "list_problems_by_type";
            def.description = "List problems by type";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "problem_type", {
                                {"type", "number"},
                                {"description", "Problem type ID"}
                            }
                        },
                        {
                            "start_address", {
                                {"type", "string"},
                                {"description", "Start hex address"}
                            }
                        },
                        {
                            "end_address", {
                                {"type", "string"},
                                {"description", "End hex address"}
                            }
                        }
                    }
                },
                {"required", json::array({"problem_type"})}
            };
            server.register_tool(def, handle_list_problems_by_type);
        }

        // get_problems_at_address
        {
            mcp::ToolDefinition def;
            def.name = "get_problems_at_address";
            def.description = "Get problems at address";
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
            server.register_tool(def, handle_get_problems_at_address);
        }

        // get_problem_type_name
        {
            mcp::ToolDefinition def;
            def.name = "get_problem_type_name";
            def.description = "Get problem type name";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "problem_type", {
                                {"type", "number"},
                                {"description", "Problem type ID (1-16)"}
                            }
                        },
                        {
                            "long_name", {
                                {"type", "boolean"},
                                {"description", "Long/short name"}
                            }
                        }
                    }
                },
                {"required", json::array({"problem_type"})}
            };
            server.register_tool(def, handle_get_problem_type_name);
        }

        // check_problem_exists
        {
            mcp::ToolDefinition def;
            def.name = "check_problem_exists";
            def.description = "Check if problem exists";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "problem_type", {
                                {"type", "number"},
                                {"description", "Problem type ID (1-16)"}
                            }
                        },
                        {
                            "address", {
                                {"type", "string"},
                                {"description", "Hex address"}
                            }
                        }
                    }
                },
                {"required", json::array({"problem_type", "address"})}
            };
            server.register_tool(def, handle_check_problem_exists);
        }
    }
} // namespace ida_mcp::tools::problems
