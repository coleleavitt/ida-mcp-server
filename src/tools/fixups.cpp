#include "tools/tools.hpp"
#include <fixup.hpp>

namespace ida_mcp::tools::fixups {
    namespace {
        json handle_list_fixups(const json &params) {
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

            json fixups = json::array();

            for (ea_t ea = get_first_fixup_ea(); ea != BADADDR; ea = get_next_fixup_ea(ea)) {
                if (ea < start_ea) continue;
                if (ea >= end_ea) break;

                fixup_data_t fd;
                if (get_fixup(&fd, ea)) {
                    qstring desc;
                    get_fixup_desc(&desc, ea, fd);

                    json fixup_obj;
                    fixup_obj["address"] = format_ea(ea);
                    fixup_obj["type"] = static_cast<uint32_t>(fd.get_type());
                    fixup_obj["type_desc"] = desc.c_str();
                    fixup_obj["target"] = format_ea(fd.off);
                    fixup_obj["displacement"] = static_cast<int64_t>(fd.displacement);

                    fixups.push_back(fixup_obj);
                }
            }

            return json{
                {"start_address", format_ea(start_ea)},
                {"end_address", format_ea(end_ea)},
                {"fixup_count", fixups.size()},
                {"fixups", fixups}
            };
        }

        json handle_get_fixup_info(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            fixup_data_t fd;
            if (!get_fixup(&fd, ea)) {
                return json{
                    {"address", format_ea(ea)},
                    {"has_fixup", false},
                    {"error", "No fixup exists at this address"}
                };
            }

            qstring desc;
            get_fixup_desc(&desc, ea, fd);

            return json{
                {"address", format_ea(ea)},
                {"has_fixup", true},
                {"type", static_cast<uint32_t>(fd.get_type())},
                {"type_desc", desc.c_str()},
                {"target", format_ea(fd.off)},
                {"displacement", static_cast<int64_t>(fd.displacement)},
                {"base", static_cast<uint64_t>(fd.get_base())}
            };
        }

        json handle_get_fixups_in_range(const json &params) {
            auto start_opt = parse_ea(params["start_address"]);
            if (!start_opt.has_value()) {
                throw std::runtime_error("Invalid start_address format");
            }
            ea_t start_ea = start_opt.value();
            uint64_t size = params["size"].get<uint64_t>();

            ea_t end_ea = start_ea + size;

            json fixups = json::array();

            for (ea_t ea = get_first_fixup_ea(); ea != BADADDR; ea = get_next_fixup_ea(ea)) {
                if (ea < start_ea) continue;
                if (ea >= end_ea) break;

                fixup_data_t fd;
                if (get_fixup(&fd, ea)) {
                    qstring desc;
                    get_fixup_desc(&desc, ea, fd);

                    json fixup_obj;
                    fixup_obj["address"] = format_ea(ea);
                    fixup_obj["type"] = static_cast<uint32_t>(fd.get_type());
                    fixup_obj["type_desc"] = desc.c_str();
                    fixup_obj["target"] = format_ea(fd.off);

                    fixups.push_back(fixup_obj);
                }
            }

            return json{
                {"start_address", format_ea(start_ea)},
                {"size", size},
                {"fixup_count", fixups.size()},
                {"fixups", fixups}
            };
        }

        json handle_count_fixups(const json &params) {
            size_t count = 0;

            for (ea_t ea = get_first_fixup_ea(); ea != BADADDR; ea = get_next_fixup_ea(ea)) {
                count++;
            }

            return json{
                {"total_fixups", count}
            };
        }

        json handle_get_fixup_type_description(const json &params) {
            uint16_t fixup_type = params["fixup_type"].get<uint16_t>();

            // For just getting type description without an address/fixup, we need a dummy fixup
            fixup_data_t fd(fixup_type);
            qstring desc;
            get_fixup_desc(&desc, BADADDR, fd);

            return json{
                {"fixup_type", fixup_type},
                {"description", desc.empty() ? "No description available" : desc.c_str()}
            };
        }
    } // anonymous namespace

    void register_tools(mcp::McpServer &server) {
        // list_fixups
        {
            mcp::ToolDefinition def;
            def.name = "list_fixups";
            def.description = "Enumerate fixups/relocations";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "start_address", {
                                {"type", "string"},
                                {"description", "Hex start"}
                            }
                        },
                        {
                            "end_address", {
                                {"type", "string"},
                                {"description", "Hex end"}
                            }
                        }
                    }
                }
            };
            server.register_tool(def, handle_list_fixups);
        }

        // get_fixup_info
        {
            mcp::ToolDefinition def;
            def.name = "get_fixup_info";
            def.description = "Get fixup info at address";
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
            server.register_tool(def, handle_get_fixup_info);
        }

        // get_fixups_in_range
        {
            mcp::ToolDefinition def;
            def.name = "get_fixups_in_range";
            def.description = "Get fixups in range";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "start_address", {
                                {"type", "string"},
                                {"description", "Hex start"}
                            }
                        },
                        {
                            "size", {
                                {"type", "number"},
                                {"description", "Size bytes"}
                            }
                        }
                    }
                },
                {"required", json::array({"start_address", "size"})}
            };
            server.register_tool(def, handle_get_fixups_in_range);
        }

        // count_fixups
        {
            mcp::ToolDefinition def;
            def.name = "count_fixups";
            def.description = "Count all fixups";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {}}
            };
            server.register_tool(def, handle_count_fixups);
        }

        // get_fixup_type_description
        {
            mcp::ToolDefinition def;
            def.name = "get_fixup_type_description";
            def.description = "Get fixup type description";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "fixup_type", {
                                {"type", "number"},
                                {"description", "Fixup type ID"}
                            }
                        }
                    }
                },
                {"required", json::array({"fixup_type"})}
            };
            server.register_tool(def, handle_get_fixup_type_description);
        }
    }
} // namespace ida_mcp::tools::fixups
