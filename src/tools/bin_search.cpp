#include "tools/tools.hpp"
#include <bytes.hpp>
#include <search.hpp>

namespace ida_mcp::tools::bin_search {
    namespace {
        json search_binary_pattern_impl(const json &params) {
            std::string pattern_str = params["pattern"].get<std::string>();
            int limit = params.value("limit", 100);

            ea_t start_ea = inf_get_min_ea();
            ea_t end_ea = inf_get_max_ea();

            if (params.contains("start_address")) {
                auto addr = parse_ea(params["start_address"]);
                if (!addr.has_value()) {
                    throw std::runtime_error("Invalid start_address");
                }
                start_ea = addr.value();
            }

            if (params.contains("end_address")) {
                auto addr = parse_ea(params["end_address"]);
                if (!addr.has_value()) {
                    throw std::runtime_error("Invalid end_address");
                }
                end_ea = addr.value();
            }

            int radix = params.value("radix", 16);

            json results = json::array();
            ea_t ea = start_ea;

            while (results.size() < static_cast<size_t>(limit) && ea < end_ea) {
                ea = find_binary(ea, end_ea, pattern_str.c_str(), radix,
                                 SEARCH_DOWN | SEARCH_NEXT);

                if (ea == BADADDR || ea >= end_ea) {
                    break;
                }

                func_t *func = get_func(ea);
                std::string func_name;
                if (func != nullptr) {
                    func_name = get_function_name(func);
                }

                results.push_back(json{
                    {"address", format_ea(ea)},
                    {"function", func_name.empty() ? nullptr : json(func_name)}
                });

                ea = ea + 1;
            }

            return json{
                {"pattern", pattern_str},
                {"radix", radix},
                {"match_count", results.size()},
                {"truncated", results.size() >= static_cast<size_t>(limit)},
                {"results", results}
            };
        }
    }

    void register_tools(mcp::McpServer &server) {
        {
            mcp::ToolDefinition def;
            def.name = "search_binary_pattern";
            def.description = "Search for binary pattern with wildcards (e.g., '48 8B ?? ?? 90')";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "pattern",
                            {
                                {"type", "string"},
                                {"description", "Binary pattern with ?? wildcards (e.g., '48 8B ?? ?? 90')"}
                            }
                        },
                        {"start_address", {{"type", "string"}, {"description", "Hex start address"}}},
                        {"end_address", {{"type", "string"}, {"description", "Hex end address"}}},
                        {"radix", {{"type", "integer"}, {"description", "Number base (default: 16)"}}},
                        {"limit", {{"type", "integer"}, {"description", "Max results (default: 100)"}}}
                    }
                },
                {"required", json::array({"pattern"})}
            };
            server.register_tool(def, search_binary_pattern_impl);
        }
    }
}
