#include "tools/tools.hpp"
#include <bytes.hpp>
#include <ua.hpp>
#include <segment.hpp>
#include <funcs.hpp>

namespace ida_mcp::tools::navigation {
    // Get the previous defined item (instruction or data)
    static json get_prev_head(const json &params) {
        auto ea_opt = parse_ea(params["address"]);
        if (!ea_opt.has_value()) {
            throw std::runtime_error("Invalid address format");
        }
        ea_t ea = ea_opt.value();

        ea_t min_ea = inf_get_min_ea();
        ea_t prev = prev_head(ea, min_ea);

        if (prev == BADADDR || prev >= ea) {
            return json{
                {"current_address", format_ea(ea)},
                {"previous_address", nullptr},
                {"note", "No previous item found"}
            };
        }

        // Get mnemonic at previous address
        qstring mnem;
        print_insn_mnem(&mnem, prev);

        return json{
            {"current_address", format_ea(ea)},
            {"previous_address", format_ea(prev)},
            {"mnemonic", mnem.empty() ? nullptr : json(mnem.c_str())}
        };
    }

    // Get the next defined item (instruction or data)
    static json get_next_head(const json &params) {
        auto ea_opt = parse_ea(params["address"]);
        if (!ea_opt.has_value()) {
            throw std::runtime_error("Invalid address format");
        }
        ea_t ea = ea_opt.value();

        ea_t max_ea = inf_get_max_ea();
        ea_t next = next_head(ea, max_ea);

        if (next == BADADDR || next <= ea) {
            return json{
                {"current_address", format_ea(ea)},
                {"next_address", nullptr},
                {"note", "No next item found"}
            };
        }

        // Get mnemonic at next address
        qstring mnem;
        print_insn_mnem(&mnem, next);

        return json{
            {"current_address", format_ea(ea)},
            {"next_address", format_ea(next)},
            {"mnemonic", mnem.empty() ? nullptr : json(mnem.c_str())}
        };
    }

    // Get function boundaries
    static json get_func_limits(const json &params) {
        auto ea_opt = parse_ea(params["address"]);
        if (!ea_opt.has_value()) {
            throw std::runtime_error("Invalid address format");
        }
        ea_t ea = ea_opt.value();

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

        return json{
            {"query_address", format_ea(ea)},
            {"function_name", name_str},
            {"start_address", format_ea(func->start_ea)},
            {"end_address", format_ea(func->end_ea)},
            {"size", func->end_ea - func->start_ea}
        };
    }

    // Get the previous item skipping tail bytes
    static json get_prev_not_tail(const json &params) {
        auto ea_opt = parse_ea(params["address"]);
        if (!ea_opt.has_value()) {
            throw std::runtime_error("Invalid address format");
        }
        ea_t ea = ea_opt.value();

        ea_t prev = prev_not_tail(ea);

        if (prev == BADADDR || prev >= ea) {
            return json{
                {"current_address", format_ea(ea)},
                {"previous_address", nullptr},
                {"note", "No previous non-tail item found"}
            };
        }

        // Get mnemonic at previous address
        qstring mnem;
        print_insn_mnem(&mnem, prev);

        return json{
            {"current_address", format_ea(ea)},
            {"previous_address", format_ea(prev)},
            {"mnemonic", mnem.empty() ? nullptr : json(mnem.c_str())}
        };
    }

    // Get the next item skipping tail bytes
    static json get_next_not_tail(const json &params) {
        auto ea_opt = parse_ea(params["address"]);
        if (!ea_opt.has_value()) {
            throw std::runtime_error("Invalid address format");
        }
        ea_t ea = ea_opt.value();

        ea_t next = next_not_tail(ea);

        if (next == BADADDR || next <= ea) {
            return json{
                {"current_address", format_ea(ea)},
                {"next_address", nullptr},
                {"note", "No next non-tail item found"}
            };
        }

        // Get mnemonic at next address
        qstring mnem;
        print_insn_mnem(&mnem, next);

        return json{
            {"current_address", format_ea(ea)},
            {"next_address", format_ea(next)},
            {"mnemonic", mnem.empty() ? nullptr : json(mnem.c_str())}
        };
    }

    // Get the previous function
    static json get_prev_func_nav(const json &params) {
        auto ea_opt = parse_ea(params["address"]);
        if (!ea_opt.has_value()) {
            throw std::runtime_error("Invalid address format");
        }
        ea_t ea = ea_opt.value();

        func_t *func = get_prev_func(ea);

        if (func == nullptr) {
            return json{
                {"current_address", format_ea(ea)},
                {"previous_function", nullptr},
                {"note", "No previous function found"}
            };
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

        return json{
            {"current_address", format_ea(ea)},
            {
                "previous_function", json{
                    {"address", format_ea(func->start_ea)},
                    {"name", name_str},
                    {"size", func->end_ea - func->start_ea}
                }
            }
        };
    }

    // Get the next function
    static json get_next_func_nav(const json &params) {
        auto ea_opt = parse_ea(params["address"]);
        if (!ea_opt.has_value()) {
            throw std::runtime_error("Invalid address format");
        }
        ea_t ea = ea_opt.value();

        func_t *func = get_next_func(ea);

        if (func == nullptr) {
            return json{
                {"current_address", format_ea(ea)},
                {"next_function", nullptr},
                {"note", "No next function found"}
            };
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

        return json{
            {"current_address", format_ea(ea)},
            {
                "next_function", json{
                    {"address", format_ea(func->start_ea)},
                    {"name", name_str},
                    {"size", func->end_ea - func->start_ea}
                }
            }
        };
    }

    // Get the first segment
    static json get_first_seg_nav(const json &params) {
        segment_t *seg = get_first_seg();

        if (seg == nullptr) {
            return json{
                {"first_segment", nullptr},
                {"note", "No segments found in database"}
            };
        }

        qstring seg_name;
        get_segm_name(&seg_name, seg);

        return json{
            {
                "first_segment", json{
                    {"name", seg_name.c_str()},
                    {"start", format_ea(seg->start_ea)},
                    {"end", format_ea(seg->end_ea)},
                    {"size", seg->end_ea - seg->start_ea}
                }
            }
        };
    }

    // Get the previous segment
    static json get_prev_seg_nav(const json &params) {
        auto ea_opt = parse_ea(params["address"]);
        if (!ea_opt.has_value()) {
            throw std::runtime_error("Invalid address format");
        }
        ea_t ea = ea_opt.value();

        segment_t *seg = get_prev_seg(ea);

        if (seg == nullptr) {
            return json{
                {"current_address", format_ea(ea)},
                {"previous_segment", nullptr},
                {"note", "No previous segment found"}
            };
        }

        qstring seg_name;
        get_segm_name(&seg_name, seg);

        return json{
            {"current_address", format_ea(ea)},
            {
                "previous_segment", json{
                    {"name", seg_name.c_str()},
                    {"start", format_ea(seg->start_ea)},
                    {"end", format_ea(seg->end_ea)},
                    {"size", seg->end_ea - seg->start_ea}
                }
            }
        };
    }

    // Get the next segment
    static json get_next_seg_nav(const json &params) {
        auto ea_opt = parse_ea(params["address"]);
        if (!ea_opt.has_value()) {
            throw std::runtime_error("Invalid address format");
        }
        ea_t ea = ea_opt.value();

        segment_t *seg = get_next_seg(ea);

        if (seg == nullptr) {
            return json{
                {"current_address", format_ea(ea)},
                {"next_segment", nullptr},
                {"note", "No next segment found"}
            };
        }

        qstring seg_name;
        get_segm_name(&seg_name, seg);

        return json{
            {"current_address", format_ea(ea)},
            {
                "next_segment", json{
                    {"name", seg_name.c_str()},
                    {"start", format_ea(seg->start_ea)},
                    {"end", format_ea(seg->end_ea)},
                    {"size", seg->end_ea - seg->start_ea}
                }
            }
        };
    }

    void register_tools(mcp::McpServer &server) {
        // get_prev_head tool
        {
            mcp::ToolDefinition def;
            def.name = "get_prev_head";
            def.description = "Get previous item address";
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
            server.register_tool(def, get_prev_head);
        }

        // get_next_head tool
        {
            mcp::ToolDefinition def;
            def.name = "get_next_head";
            def.description = "Get next item address";
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
            server.register_tool(def, get_next_head);
        }

        // get_func_limits tool
        {
            mcp::ToolDefinition def;
            def.name = "get_func_limits";
            def.description = "Get function boundaries";
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
            server.register_tool(def, get_func_limits);
        }

        // get_prev_not_tail tool
        {
            mcp::ToolDefinition def;
            def.name = "get_prev_not_tail";
            def.description = "Get previous item skipping tail bytes";
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
            server.register_tool(def, get_prev_not_tail);
        }

        // get_next_not_tail tool
        {
            mcp::ToolDefinition def;
            def.name = "get_next_not_tail";
            def.description = "Get next item skipping tail bytes";
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
            server.register_tool(def, get_next_not_tail);
        }

        // get_prev_func tool
        {
            mcp::ToolDefinition def;
            def.name = "get_prev_func";
            def.description = "Get previous function";
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
            server.register_tool(def, get_prev_func_nav);
        }

        // get_next_func tool
        {
            mcp::ToolDefinition def;
            def.name = "get_next_func";
            def.description = "Get next function";
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
            server.register_tool(def, get_next_func_nav);
        }

        // get_first_seg tool
        {
            mcp::ToolDefinition def;
            def.name = "get_first_seg";
            def.description = "Get first segment";
            def.input_schema = json{
                {"type", "object"},
                {"properties", json::object()}
            };
            server.register_tool(def, get_first_seg_nav);
        }

        // get_prev_seg tool
        {
            mcp::ToolDefinition def;
            def.name = "get_prev_seg";
            def.description = "Get previous segment";
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
            server.register_tool(def, get_prev_seg_nav);
        }

        // get_next_seg tool
        {
            mcp::ToolDefinition def;
            def.name = "get_next_seg";
            def.description = "Get next segment";
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
            server.register_tool(def, get_next_seg_nav);
        }
    }
} // namespace ida_mcp::tools::navigation
