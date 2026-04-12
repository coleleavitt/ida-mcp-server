#include "tools/tools.hpp"
#include <bytes.hpp>
#include <segment.hpp>
#include <lines.hpp>
#include <ida.hpp>
#include <regex.h>

namespace ida_mcp::tools::search {
    namespace {
        // Helper: Check if this is a Mach-O binary
        bool is_macho_binary() {
            return inf_get_filetype() == f_MACHO;
        }

        // Helper: Search for Objective-C selectors in __objc_methname section
        json search_objc_section(const std::string &pattern, const char *section_name,
                                const char *alt_name, const char *result_key,
                                const char *result_type, int limit) {
            json results = json::array();

            segment_t *seg = get_segm_by_name(section_name);
            if (seg == nullptr && alt_name != nullptr)
                seg = get_segm_by_name(alt_name);
            if (seg == nullptr)
                return results;

            struct regex_t re;
            if (qregcomp(&re, pattern.c_str(), REG_ICASE | REG_NOSUB) != 0)
                return results;

            ea_t ea = seg->start_ea;
            while (ea < seg->end_ea && results.size() < (size_t)limit) {
                qstring str;
                size_t len = get_max_strlit_length(ea, STRTYPE_C, ALOPT_IGNHEADS);
                if (len > 0 && len < 1024) {
                    if (get_strlit_contents(&str, ea, len, STRTYPE_C)) {
                        if (qregexec(&re, str.c_str(), 0, nullptr, 0) == 0) {
                            results.push_back(json{
                                {"address", format_ea(ea)},
                                {result_key, str.c_str()},
                                {"type", result_type}
                            });
                        }
                        ea += len + 1;
                        continue;
                    }
                }
                ea = next_head(ea, seg->end_ea);
            }

            qregfree(&re);
            return results;
        }
    } // anonymous namespace

    static json search_disassembly(const json &params) {
        // Parse parameters
        if (!params.contains("pattern") || !params["pattern"].is_string()) {
            throw std::runtime_error("Missing required parameter: pattern");
        }

        std::string pattern = params["pattern"];
        int limit = params.value("limit", 100);
        bool case_insensitive = params.value("case_insensitive", false);

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

        json results = json::array();

        // Check if pattern is a simple string (no regex metacharacters)
        int sflag = SEARCH_DOWN | SEARCH_NOSHOW;
        if (!case_insensitive)
            sflag |= SEARCH_CASE;

        bool has_regex_chars = pattern.find_first_of("*+?[](){}|^$\\.") != std::string::npos;
        if (has_regex_chars || case_insensitive)
            sflag |= SEARCH_REGEX;

        ea_t ea = start_ea;
        while (results.size() < (size_t) limit) {
            ea = find_text(ea, 0, 0, pattern.c_str(), sflag);

            if (ea == BADADDR || ea >= end_ea)
                break;

            qstring disasm, clean_disasm;
            generate_disasm_line(&disasm, ea, GENDSM_FORCE_CODE);
            tag_remove(&clean_disasm, disasm);

            func_t *func = get_func(ea);
            std::string func_name;
            if (func != nullptr)
                func_name = get_function_name(func);

            results.push_back(json{
                {"address", format_ea(ea)},
                {"disassembly", clean_disasm.c_str()},
                {"function", func_name.empty() ? nullptr : json(func_name)}
            });

            ea = next_head(ea, end_ea);
            if (ea == BADADDR)
                break;
        }

        json response = json{
            {"pattern", pattern},
            {"case_insensitive", case_insensitive},
            {"match_count", results.size()},
            {"truncated", results.size() >= (size_t) limit},
            {"results", results}
        };

        // For Mach-O binaries, also search Objective-C sections if pattern looks like a selector
        if (is_macho_binary() && results.size() < (size_t) limit) {
            // Check if pattern might be an Objective-C selector (contains : or starts with common prefixes)
            bool looks_like_selector = pattern.find(':') != std::string::npos ||
                                       pattern.find("init") != std::string::npos ||
                                       pattern.find("alloc") != std::string::npos ||
                                       pattern.find("dealloc") != std::string::npos ||
                                       pattern.find("set") != std::string::npos ||
                                       pattern.find("get") != std::string::npos;

            if (looks_like_selector) {
                json objc_selectors = search_objc_section(
                    pattern, "__TEXT,__objc_methname", "__objc_methname",
                    "selector", "objc_selector", limit - results.size());
                if (!objc_selectors.empty()) {
                    response["objc_selectors"] = objc_selectors;
                    response["objc_selector_count"] = objc_selectors.size();
                }
            }

            json objc_classes = search_objc_section(
                pattern, "__TEXT,__objc_classname", "__objc_classname",
                "classname", "objc_class", limit - results.size());
            if (!objc_classes.empty()) {
                response["objc_classes"] = objc_classes;
                response["objc_class_count"] = objc_classes.size();
            }
        }

        return response;
    }

    static json search_bytes_impl(const json &params) {
        std::string pattern_str = params["pattern"].get<std::string>();
        int limit = params.value("limit", 100);

        // Remove spaces from pattern
        std::string hex_pattern;
        for (char c: pattern_str) {
            if (c != ' ' && c != '\t') {
                hex_pattern += c;
            }
        }

        // Convert hex string to byte array
        if (hex_pattern.length() % 2 != 0) {
            throw std::runtime_error("Hex pattern must have even number of characters");
        }

        std::vector<uchar> pattern_bytes;
        for (size_t i = 0; i < hex_pattern.length(); i += 2) {
            std::string byte_str = hex_pattern.substr(i, 2);
            uchar byte = static_cast<uchar>(std::stoul(byte_str, nullptr, 16));
            pattern_bytes.push_back(byte);
        }

        if (pattern_bytes.empty()) {
            throw std::runtime_error("Empty pattern");
        }

        ea_t start_ea = inf_get_min_ea();
        ea_t end_ea = inf_get_max_ea();

        if (params.contains("start_address")) {
            auto start_opt = parse_ea(params["start_address"]);
            if (!start_opt.has_value()) {
                throw std::runtime_error("Invalid start_address format");
            }
            start_ea = start_opt.value();
        }

        if (params.contains("end_address")) {
            auto end_opt = parse_ea(params["end_address"]);
            if (!end_opt.has_value()) {
                throw std::runtime_error("Invalid end_address format");
            }
            end_ea = end_opt.value();
        }

        json results = json::array();
        ea_t ea = start_ea;

        while (results.size() < (size_t) limit && ea < end_ea) {
            // Use bin_search to find pattern
            ea = ::bin_search(ea, end_ea, pattern_bytes.data(), nullptr,
                              pattern_bytes.size(), BIN_SEARCH_FORWARD);

            if (ea == BADADDR) {
                break;
            }

            results.push_back(json{
                {"address", format_ea(ea)},
                {"size", pattern_bytes.size()}
            });

            // Move past this match to find next
            ea = ea + 1;
        }

        return json{
            {"pattern", pattern_str},
            {"match_count", results.size()},
            {"truncated", results.size() >= (size_t) limit},
            {"results", results}
        };
    }

    static json get_segment_perms_impl(const json &params) {
        auto ea_opt = parse_ea(params["address"]);
        if (!ea_opt.has_value()) {
            throw std::runtime_error("Invalid address format");
        }
        ea_t ea = ea_opt.value();

        segment_t *seg = getseg(ea);
        if (seg == nullptr) {
            throw std::runtime_error("No segment at " + format_ea(ea));
        }

        qstring seg_name;
        get_segm_name(&seg_name, seg);

        bool readable = true; // All IDA segments are readable
        bool writable = (seg->perm & SEGPERM_WRITE) != 0;
        bool executable = (seg->perm & SEGPERM_EXEC) != 0;

        return json{
            {"address", format_ea(ea)},
            {"segment_name", seg_name.c_str()},
            {"segment_start", format_ea(seg->start_ea)},
            {"segment_end", format_ea(seg->end_ea)},
            {
                "permissions", {
                    {"read", readable},
                    {"write", writable},
                    {"execute", executable}
                }
            },
            {"perm_value", seg->perm}
        };
    }

    void register_tools(mcp::McpServer &server) {
        // search_disassembly
        {
            mcp::ToolDefinition def;
            def.name = "search_disassembly";
            def.description = "Search disassembly for pattern";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "pattern", {
                                {"type", "string"},
                                {"description", "Search pattern"}
                            }
                        },
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
                        },
                        {
                            "limit", {
                                {"type", "integer"},
                                {"description", "Max results"}
                            }
                        },
                        {
                            "case_insensitive", {
                                {"type", "boolean"},
                                {"description", "Case insensitive"}
                            }
                        }
                    }
                },
                {"required", json::array({"pattern"})}
            };
            server.register_tool(def, search_disassembly);
        }

        // search_bytes
        {
            mcp::ToolDefinition def;
            def.name = "search_bytes";
            def.description = "Search for hex byte pattern";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "pattern", {
                                {"type", "string"},
                                {"description", "Hex pattern"}
                            }
                        },
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
                        },
                        {
                            "limit", {
                                {"type", "number"},
                                {"description", "Max results"},
                                {"default", 100}
                            }
                        }
                    }
                },
                {"required", json::array({"pattern"})}
            };
            server.register_tool(def, search_bytes_impl);
        }

        // get_segment_perms
        {
            mcp::ToolDefinition def;
            def.name = "get_segment_perms";
            def.description = "Get segment permissions";
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
            server.register_tool(def, get_segment_perms_impl);
        }
    }
} // namespace ida_mcp::tools::search
