#include "tools/tools.hpp"
#include <strlist.hpp>
#include <bytes.hpp>
#include <xref.hpp>

namespace ida_mcp::tools::strings {
    namespace {
        json provider_json(uchar id) {
            const char *name = synth_string_provider_name(id);
            return json{{"id", id}, {"name", name != nullptr ? json(name) : json(nullptr)}};
        }

        std::optional<ea_t> optional_ea(const json &params, const char *key) {
            if (!params.contains(key))
                return std::nullopt;
            if (!params[key].is_string())
                throw std::runtime_error(std::string(key) + " must be a hex address string");
            auto ea = parse_ea(params[key].get<std::string>());
            if (!ea)
                throw std::runtime_error(std::string("Invalid address in ") + key);
            return ea;
        }
    }

    // List and search strings in the binary
    static json list_strings(const json &params) {
        std::string query = params.value("query", "");
        int limit = params.value("limit", 100);
        limit = std::min(limit, 1000); // Cap at 1000
        bool case_sensitive = params.value("case_sensitive", false);

        // Check binary size FIRST - before touching string list APIs
        // Large binaries can cause heap corruption when string list isn't built
        size_t func_count = get_func_qty();
        
        // Safe to query string list now (but check the count)
        size_t total_strings = get_strlist_qty();
        
        // Refuse to iterate if too many strings - can cause crashes on complex binaries
        if (total_strings > 100000) {
            return json{
                {"count", 0},
                {"query", query.empty() ? nullptr : json(query)},
                {"strings", json::array()},
                {
                    "note", "String list is very large (" + std::to_string(total_strings) +
                            " strings). Operations disabled to prevent crashes. "
                            "Use get_string_at with specific addresses instead."
                },
                {
                    "diagnostic", {
                        {"function_count", func_count},
                        {"string_count", total_strings},
                        {"is_large_binary", true}
                    }
                }
            };
        }

        if (total_strings == 0 && func_count < 50000) {
            // Small binary with no strings - safe to build
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
            
            // Re-check after build
            if (total_strings > 100000) {
                return json{
                    {"count", 0},
                    {"query", query.empty() ? nullptr : json(query)},
                    {"strings", json::array()},
                    {"note", "String list too large after build (" + std::to_string(total_strings) + " strings)."}
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
            string_info_ex_t si;
            if (!get_strlist_item_ex(&si, i)) {
                continue;
            }

            ea_t ea = si.ea;
            if (ea == BADADDR) continue;

            // A synthetic string (STRTYPE_SYNTH) is not in the bytes: the list
            // carries its text.
            const bool synthetic = is_synth_strtype(si.type);
            std::string content;
            if (synthetic) {
                content = si.synthetic_string.c_str();
            } else {
                if (si.length == 0 || si.length > 0x100000) continue;  // Skip zero-length or absurdly long
                qstring str_content;
                if (get_strlit_contents(&str_content, ea, si.length, si.type) <= 0) continue;
                content = str_content.c_str();
            }
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

            json entry = {
                {"address", format_ea(ea)},
                {"content", content},
                {"length", content.length()}
            };
            if (synthetic) {
                entry["synthetic"] = true;
                entry["provider"] = provider_json(get_synth_provider_id(si.type));
            }
            string_list.push_back(std::move(entry));
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

    // Synthetic strings stored by providers (Hex-Rays, Swift, plugins); they
    // are not in the bytes, and every provider's text at an address is listed.
    static json list_synthetic_strings(const json &params) {
        const ea_t start = optional_ea(params, "start").value_or(inf_get_min_ea());
        const ea_t end = optional_ea(params, "end").value_or(inf_get_max_ea());
        if (end <= start)
            throw std::runtime_error("end must be greater than start");
        const int64 offset = std::max<int64>(0, params.value("offset", int64(0)));
        const int64 count = std::max<int64>(1, params.value("count", int64(100)));

        synth_strings_t found;
        synth_string_get_range(&found, start, end);
        const auto total = static_cast<int64>(found.size());
        const int64 stop = std::min(total, offset + count);

        json items = json::array();
        for (int64 i = offset; i < stop; ++i) {
            const synth_string_t &ss = found[static_cast<size_t>(i)];
            json flags = json::array();
            if ((ss.flags & SYNTHSTR_NOCMT) != 0) flags.push_back("nocmt");
            if ((ss.flags & SYNTHSTR_REPEATABLE) != 0) flags.push_back("repeatable");
            items.push_back(json{
                {"address", format_ea(ss.ea)},
                {"content", ss.text.c_str()},
                {"provider", provider_json(ss.provider)},
                {"flags", flags}
            });
        }
        return json{
            {"total", total},
            {"offset", offset},
            {"strings", items},
            {"next_offset", stop < total ? json(stop) : json(nullptr)}
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

        {
            mcp::ToolDefinition def;
            def.name = "list_synthetic_strings";
            def.description = "List synthetic strings: text that providers (Hex-Rays, Swift, plugins) stored "
                    "for addresses because it is not in the bytes, e.g. strings built from immediates";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"start", {{"type", "string"}, {"description", "Hex start (default: database start)"}}},
                    {"end", {{"type", "string"}, {"description", "Hex end, exclusive (default: database end)"}}},
                    {"offset", {{"type", "integer"}, {"minimum", 0}, {"default", 0}}},
                    {"count", {{"type", "integer"}, {"minimum", 1}, {"default", 100}}}
                }}
            };
            server.register_tool(def, list_synthetic_strings);
        }
    }
} // namespace ida_mcp::tools::strings
