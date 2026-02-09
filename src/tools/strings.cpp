#include "tools/tools.hpp"
#include <strlist.hpp>
#include <bytes.hpp>
#include <xref.hpp>

namespace ida_mcp::tools::strings {
    // List and search strings in the binary
    static json list_strings(const json &params) {
        std::string query = params.value("query", "");
        int limit = params.value("limit", 100);
        limit = std::min(limit, 1000); // Cap at 1000
        bool case_sensitive = params.value("case_sensitive", false);

        // Check if string list exists, build if needed
        size_t total_strings = get_strlist_qty();

        if (total_strings == 0) {
            // Check binary size before auto-building
            size_t func_count = get_func_qty();

            if (func_count > 50000) {
                // Binary too large - refuse to auto-build
                return json{
                    {"count", 0},
                    {"query", query.empty() ? nullptr : json(query)},
                    {"strings", json::array()},
                    {
                        "note", "String list is empty. Binary is very large (" + std::to_string(func_count) +
                                " functions). Please build string list manually in IDA: View → Strings (Shift+F12)"
                    },
                    {
                        "diagnostic", {
                            {"function_count", func_count},
                            {"strlist_qty", 0},
                            {"requires_manual_build", true},
                            {"is_large_binary", true}
                        }
                    }
                };
            }

            // Small binary - safe to build
            build_strlist();
            total_strings = get_strlist_qty();

            if (total_strings == 0) {
                return json{
                    {"count", 0},
                    {"query", query.empty() ? nullptr : json(query)},
                    {"strings", json::array()},
                    {"note", "String list is empty after build. Database may not contain strings."}
                };
            }
        }

        // Iterate through strings
        json string_list = json::array();
        bool has_query = !query.empty();
        std::string search_query = case_sensitive
                                       ? query
                                       : [&query]() {
                                           std::string lower = query;
                                           std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
                                           return lower;
                                       }();

        for (size_t i = 0; i < total_strings && string_list.size() < (size_t) limit; i++) {
            string_info_t si;
            if (!get_strlist_item(&si, i)) {
                continue;
            }

            ea_t ea = si.ea;
            if (ea == BADADDR) continue;

            // Get string content
            qstring str_content;
            ssize_t len = get_strlit_contents(&str_content, ea, -1, STRTYPE_C);
            if (len <= 0) continue;

            std::string content = str_content.c_str();
            if (content.empty()) continue;

            // Apply search filter
            if (has_query) {
                bool matches;
                if (case_sensitive) {
                    matches = content.find(search_query) != std::string::npos;
                } else {
                    std::string lower_content = content;
                    std::transform(lower_content.begin(), lower_content.end(),
                                   lower_content.begin(), ::tolower);
                    matches = lower_content.find(search_query) != std::string::npos;
                }

                if (!matches) continue;
            }

            string_list.push_back(json{
                {"address", format_ea(ea)},
                {"content", content},
                {"length", content.length()}
            });
        }

        return json{
            {"count", string_list.size()},
            {"query", query.empty() ? nullptr : json(query)},
            {"strings", string_list}
        };
    }

    // Get detailed information about a string at a specific address
    static json get_string_at(const json &params) {
        auto ea_opt = parse_ea(params["address"]);
        if (!ea_opt.has_value()) {
            throw std::runtime_error("Invalid address format");
        }
        ea_t ea = ea_opt.value();

        // Get max string length at this address
        ssize_t max_len = get_max_strlit_length(ea, STRTYPE_C, ALOPT_IGNHEADS);

        if (max_len <= 0) {
            throw std::runtime_error("No string found at address " + format_ea(ea));
        }

        // Get string content
        qstring str_content;
        ssize_t len = get_strlit_contents(&str_content, ea, max_len, STRTYPE_C);

        if (len <= 0) {
            throw std::runtime_error("Failed to read string at address " + format_ea(ea));
        }

        std::string content = str_content.c_str();

        // Get cross-references to this string
        json xrefs = json::array();
        xrefblk_t xb;
        for (bool ok = xb.first_to(ea, XREF_DATA); ok && xrefs.size() < 100; ok = xb.next_to()) {
            xrefs.push_back(format_ea(xb.from));
        }

        return json{
            {"address", format_ea(ea)},
            {"content", content},
            {"length", content.length()},
            {"max_length", max_len},
            {"xref_count", xrefs.size()},
            {"xrefs", xrefs}
        };
    }

    void register_tools(mcp::McpServer &server) {
        // list_strings tool
        {
            mcp::ToolDefinition def;
            def.name = "list_strings";
            def.description = "List and search strings";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "query", {
                                {"type", "string"},
                                {"description", "Search query"}
                            }
                        },
                        {
                            "limit", {
                                {"type", "integer"},
                                {"description", "Max results"},
                                {"default", 100}
                            }
                        },
                        {
                            "case_sensitive", {
                                {"type", "boolean"},
                                {"description", "Case sensitive"},
                                {"default", false}
                            }
                        }
                    }
                }
            };
            server.register_tool(def, list_strings);
        }

        // get_string_at tool
        {
            mcp::ToolDefinition def;
            def.name = "get_string_at";
            def.description = "Get string at address";
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
            server.register_tool(def, get_string_at);
        }
    }
} // namespace ida_mcp::tools::strings
