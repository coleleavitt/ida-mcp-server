#include "tools/tools.hpp"
#include <name.hpp>
#include <nalt.hpp>

namespace ida_mcp::tools::symbols {
    namespace {
        json handle_get_name_origin(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            // Get the name at this address
            qstring name;
            get_name(&name, ea);

            if (name.empty()) {
                return json{
                    {"address", format_ea(ea)},
                    {"has_name", false},
                    {"note", "No name defined at this address"}
                };
            }

            // Check various name properties
            bool is_user_defined = is_uname(name.c_str());
            bool is_public = is_public_name(ea);
            bool is_weak = is_weak_name(ea);

            // Determine primary origin classification
            const char *origin;
            if (!is_user_defined) {
                origin = "auto_generated";
            } else if (is_public) {
                origin = "user_defined_public";
            } else {
                origin = "user_defined";
            }

            return json{
                {"address", format_ea(ea)},
                {"name", name.c_str()},
                {"has_name", true},
                {"origin", origin},
                {
                    "classification", {
                        {"is_auto_generated", !is_user_defined},
                        {"is_user_defined", is_user_defined},
                        {"is_public", is_public},
                        {"is_weak", is_weak}
                    }
                }
            };
        }

        json handle_get_all_names_in_range(const json &params) {
            auto start_ea_opt = parse_ea(params["start_address"]);
            if (!start_ea_opt.has_value()) {
                throw std::runtime_error("Invalid start_address format");
            }
            ea_t start_ea = start_ea_opt.value();

            auto end_ea_opt = parse_ea(params["end_address"]);
            if (!end_ea_opt.has_value()) {
                throw std::runtime_error("Invalid end_address format");
            }
            ea_t end_ea = end_ea_opt.value();

            if (start_ea >= end_ea) {
                throw std::runtime_error("Start address must be less than end address");
            }

            int64_t limit_raw = params.contains("limit") && !params["limit"].is_null()
                               ? params["limit"].get<int64_t>()
                               : 1000;
            size_t limit = (limit_raw <= 0) ? 1000 : static_cast<size_t>(limit_raw);

            json names = json::array();
            size_t count = 0;

            for (ea_t ea = start_ea; ea < end_ea && count < limit;) {
                qstring name;
                get_name(&name, ea);

                if (!name.empty()) {
                    // Check origin
                    bool is_user_defined = is_uname(name.c_str());
                    bool is_public = is_public_name(ea);
                    bool is_weak = is_weak_name(ea);

                    const char *origin;
                    if (!is_user_defined) {
                        origin = "auto_generated";
                    } else if (is_public) {
                        origin = "user_defined_public";
                    } else {
                        origin = "user_defined";
                    }

                    json name_obj;
                    name_obj["address"] = format_ea(ea);
                    name_obj["name"] = name.c_str();
                    name_obj["origin"] = origin;
                    name_obj["classification"] = {
                        {"is_auto_generated", !is_user_defined},
                        {"is_user_defined", is_user_defined},
                        {"is_public", is_public},
                        {"is_weak", is_weak}
                    };

                    names.push_back(name_obj);
                    count++;
                }

                // Move to next address
                ea = next_head(ea, end_ea);
                if (ea == BADADDR) {
                    break;
                }
            }

            return json{
                {"start_address", format_ea(start_ea)},
                {"end_address", format_ea(end_ea)},
                {"name_count", names.size()},
                {"truncated", count >= limit},
                {"names", names}
            };
        }
    } // anonymous namespace

    void register_tools(mcp::McpServer &server) {
        // get_name_origin
        {
            mcp::ToolDefinition def;
            def.name = "get_name_origin";
            def.description = "Get name origin and classification";
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
            server.register_tool(def, handle_get_name_origin);
        }

        // get_all_names_in_range
        {
            mcp::ToolDefinition def;
            def.name = "get_all_names_in_range";
            def.description = "Get symbols in address range";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
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
                        },
                        {
                            "limit", {
                                {"type", "number"},
                                {"description", "Max results"}
                            }
                        }
                    }
                },
                {"required", json::array({"start_address", "end_address"})}
            };
            server.register_tool(def, handle_get_all_names_in_range);
        }
    }
} // namespace ida_mcp::tools::symbols
