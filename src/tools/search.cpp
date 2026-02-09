#include "tools/tools.hpp"
#include <regex>
#include <bytes.hpp>
#include <segment.hpp>
#include <lines.hpp>
#include <ida.hpp>

namespace ida_mcp::tools::search {
    namespace {
        // Helper: Check if this is a Mach-O binary
        bool is_macho_binary() {
            return inf_get_filetype() == f_MACHO;
        }

        // Helper: Search for Objective-C selectors in __objc_methname section
        json search_objc_selectors(const std::string &pattern, int limit) {
            json results = json::array();

            // Try to find __objc_methname section (Objective-C method names)
            segment_t *seg = get_segm_by_name("__TEXT,__objc_methname");
            if (seg == nullptr) {
                seg = get_segm_by_name("__objc_methname");
            }

            if (seg == nullptr) {
                return results; // No Objective-C method names section
            }

            std::regex re(pattern, std::regex::icase);
            ea_t ea = seg->start_ea;

            while (ea < seg->end_ea && results.size() < (size_t) limit) {
                // Read string at this address
                qstring str;
                size_t len = get_max_strlit_length(ea, STRTYPE_C, ALOPT_IGNHEADS);
                if (len > 0 && len < 1024) {
                    if (get_strlit_contents(&str, ea, len, STRTYPE_C)) {
                        std::string selector = str.c_str();

                        // Check if matches pattern
                        if (std::regex_search(selector, re)) {
                            results.push_back(json{
                                {"address", format_ea(ea)},
                                {"selector", selector},
                                {"type", "objc_selector"}
                            });
                        }

                        ea += len + 1; // Move past this string
                        continue;
                    }
                }

                ea = next_head(ea, seg->end_ea);
            }

            return results;
        }

        // Helper: Search for Objective-C class names in __objc_classname section
        json search_objc_classnames(const std::string &pattern, int limit) {
            json results = json::array();

            // Try to find __objc_classname section
            segment_t *seg = get_segm_by_name("__TEXT,__objc_classname");
            if (seg == nullptr) {
                seg = get_segm_by_name("__objc_classname");
            }

            if (seg == nullptr) {
                return results; // No Objective-C class names section
            }

            std::regex re(pattern, std::regex::icase);
            ea_t ea = seg->start_ea;

            while (ea < seg->end_ea && results.size() < (size_t) limit) {
                // Read string at this address
                qstring str;
                size_t len = get_max_strlit_length(ea, STRTYPE_C, ALOPT_IGNHEADS);
                if (len > 0 && len < 1024) {
                    if (get_strlit_contents(&str, ea, len, STRTYPE_C)) {
                        std::string classname = str.c_str();

                        // Check if matches pattern
                        if (std::regex_search(classname, re)) {
                            results.push_back(json{
                                {"address", format_ea(ea)},
                                {"classname", classname},
                                {"type", "objc_class"}
                            });
                        }

                        ea += len + 1; // Move past this string
                        continue;
                    }
                }

                ea = next_head(ea, seg->end_ea);
            }

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
        bool is_simple = pattern.find_first_of("*+?[](){}|^$\\.") == std::string::npos;

        if (is_simple && !case_insensitive) {
            ea_t ea = start_ea;

            while (results.size() < (size_t) limit) {
                ea = find_text(ea, 0, 0, pattern.c_str(), SEARCH_DOWN);

                if (ea == BADADDR || ea >= end_ea) {
                    break;
                }

                qstring disasm;
                generate_disasm_line(&disasm, ea, GENDSM_FORCE_CODE);
                qstring clean_disasm;
                tag_remove(&clean_disasm, disasm);

                func_t *func = get_func(ea);
                std::string func_name;
                if (func != nullptr) {
                    func_name = get_function_name(func);
                }

                results.push_back(json{
                    {"address", format_ea(ea)},
                    {"disassembly", clean_disasm.c_str()},
                    {"function", func_name.empty() ? nullptr : json(func_name)}
                });

                ea = next_head(ea, end_ea);
                if (ea == BADADDR) {
                    break;
                }
            }
        } else {
            std::regex re(pattern, case_insensitive ? std::regex::icase : std::regex::ECMAScript);

            for (ea_t ea = start_ea; ea < end_ea && results.size() < (size_t) limit;) {
                if (is_code(get_flags(ea))) {
                    qstring disasm;
                    generate_disasm_line(&disasm, ea, GENDSM_FORCE_CODE);
                    qstring clean_disasm;
                    tag_remove(&clean_disasm, disasm);
                    std::string disasm_str = clean_disasm.c_str();

                    if (std::regex_search(disasm_str, re)) {
                        func_t *func = get_func(ea);
                        std::string func_name;
                        if (func != nullptr) {
                            func_name = get_function_name(func);
                        }

                        results.push_back(json{
                            {"address", format_ea(ea)},
                            {"disassembly", disasm_str},
                            {"function", func_name.empty() ? nullptr : json(func_name)}
                        });
                    }
                }

                ea = next_head(ea, end_ea);
                if (ea == BADADDR) {
                    break;
                }
            }
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
                json objc_selectors = search_objc_selectors(pattern, limit - results.size());
                if (!objc_selectors.empty()) {
                    response["objc_selectors"] = objc_selectors;
                    response["objc_selector_count"] = objc_selectors.size();
                }
            }

            // Also search for class names
            json objc_classes = search_objc_classnames(pattern, limit - results.size());
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
