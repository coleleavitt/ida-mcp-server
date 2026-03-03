#include "tools/tools.hpp"
#include <array>
#include <loader.hpp>
#include <auto.hpp>

namespace ida_mcp::tools::database {
    static json get_database_info(const json &params) {
        (void) params; // Unused
        // Get database information
        std::array<char, QMAXPATH> input_file{};
        get_input_file_path(input_file.data(), input_file.size());

        auto func_count = static_cast<int>(get_func_qty());
        auto seg_count = static_cast<int>(get_segm_qty());

        ea_t min_ea = inf_get_min_ea();
        ea_t max_ea = inf_get_max_ea();
        ea_t entry = inf_get_start_ea();

        qstring proc_name = inf_get_procname();

        constexpr int BITNESS_64 = 64;
        constexpr int BITNESS_32 = 32;
        constexpr int BITNESS_16 = 16;

        return json{
            {"database_path", input_file.data()},
            {"processor", proc_name.c_str()},
            {"function_count", func_count},
            {"segment_count", seg_count},
            {"min_ea", format_ea(min_ea)},
            {"max_ea", format_ea(max_ea)},
            {"entry_point", format_ea(entry)},
            {"bitness", inf_is_64bit() ? BITNESS_64 : (inf_is_32bit_or_higher() ? BITNESS_32 : BITNESS_16)}
        };
    }

    // Note: save_database is available in plugins
    static json handle_save_database(const json &params) {
        const char *outfile = nullptr;
        uint32 flags = static_cast<uint32>(-1);

        // Check for optional output file path
        std::string path_storage;  // Local storage for the path string
        if (params.contains("outfile") && !params["outfile"].is_null()) {
            path_storage = params["outfile"].get<std::string>();
            outfile = path_storage.c_str();
        }

        // Check for optional flags
        if (params.contains("flags") && !params["flags"].is_null()) {
            flags = params["flags"].get<uint32>();
        }

        bool success = save_database(outfile, flags);

        json result = json{
            {"success", success},
            {"flags", flags}
        };

        if (outfile != nullptr) {
            result["outfile"] = outfile;
        } else {
            result["note"] = "Saved to current database location";
        }

        return result;
    }

    // Note: close_database and open_database are idalib-only (not available in plugin mode)

    // Wait for auto-analysis to complete
    static json handle_auto_wait(const json &params) {
        (void) params; // Unused
        auto_wait();

        return json{
            {"completed", true},
            {"note", "Auto-analysis has completed"}
        };
    }

    // Check auto-analysis state
    static json handle_get_auto_state(const json &params) {
        (void) params; // Unused
        atype_t state = get_auto_state();

        const char *state_str = "unknown";
        switch (state) {
            case AU_NONE: state_str = "none";
                break;
            case AU_UNK: state_str = "analyzing";
                break;
            case AU_CODE: state_str = "analyzing_code";
                break;
            case AU_WEAK: state_str = "weak_analysis";
                break;
            case AU_PROC: state_str = "processing";
                break;
            case AU_USED: state_str = "used";
                break;
            case AU_TYPE: state_str = "type_analysis";
                break;
            case AU_LIBF: state_str = "library_function";
                break;
            case AU_FINAL: state_str = "final";
                break;
        }

        bool is_auto = is_auto_enabled();
        bool analysis_complete = (state == AU_NONE || state == AU_FINAL);

        json result;
        result["state"] = state_str;
        result["state_code"] = static_cast<int>(state);
        result["auto_enabled"] = is_auto;
        result["analysis_complete"] = analysis_complete;

        return result;
    }

    // Check if database is trusted
    static json handle_is_trusted_idb(const json &params) {
        (void) params; // Unused
        bool trusted = is_trusted_idb();

        return json{
            {"trusted", trusted},
            {"note", trusted ? "Database is trusted" : "Database is NOT trusted - may contain malicious content"}
        };
    }

    // Get database flag
    static json handle_get_database_flag(const json &params) {
        if (!params.contains("flag") || params["flag"].is_null()) {
            throw std::runtime_error("flag parameter is required");
        }

        uint32 flag = params["flag"].get<uint32>();
        bool is_set = is_database_flag(flag);

        return json{
            {"flag", flag},
            {"is_set", is_set}
        };
    }

    // Set database flag
    static json handle_set_database_flag(const json &params) {
        if (!params.contains("flag") || params["flag"].is_null()) {
            throw std::runtime_error("flag parameter is required");
        }

        uint32 flag = params["flag"].get<uint32>();
        bool value = true;

        if (params.contains("value") && !params["value"].is_null()) {
            value = params["value"].get<bool>();
        }

        set_database_flag(flag, value);

        return json{
            {"flag", flag},
            {"value", value},
            {"success", true}
        };
    }

    // Get various file paths
    static json handle_get_path(const json &params) {
        if (!params.contains("path_type") || params["path_type"].is_null()) {
            throw std::runtime_error("path_type parameter is required (0=CMD, 1=IDB, 2=ID0)");
        }

        int path_type_int = params["path_type"].get<int>();
        path_type_t path_type = static_cast<path_type_t>(path_type_int);

        const char *path = get_path(path_type);

        const char *type_str = "unknown";
        switch (path_type) {
            case PATH_TYPE_CMD: type_str = "command_line";
                break;
            case PATH_TYPE_IDB: type_str = "idb_file";
                break;
            case PATH_TYPE_ID0: type_str = "id0_file";
                break;
        }

        return json{
            {"path_type", type_str},
            {"path", path ? path : ""}
        };
    }

    // Note: make_signatures is idalib-only (not available in plugin mode)

    // Plan analysis and wait for completion
    static json handle_plan_and_wait(const json &params) {
        auto ea1_opt = parse_ea(params["start_address"]);
        if (!ea1_opt.has_value()) {
            throw std::runtime_error("Invalid start_address format");
        }
        ea_t ea1 = ea1_opt.value();

        auto ea2_opt = parse_ea(params["end_address"]);
        if (!ea2_opt.has_value()) {
            throw std::runtime_error("Invalid end_address format");
        }
        ea_t ea2 = ea2_opt.value();

        bool final_pass = true;
        if (params.contains("final_pass") && !params["final_pass"].is_null()) {
            final_pass = params["final_pass"].get<bool>();
        }

        int result = plan_and_wait(ea1, ea2, final_pass);

        return json{
            {"start_address", format_ea(ea1)},
            {"end_address", format_ea(ea2)},
            {"final_pass", final_pass},
            {"result", result},
            {"completed", true}
        };
    }

    // Mark range for auto-analysis
    static json handle_auto_mark_range(const json &params) {
        auto ea1_opt = parse_ea(params["start_address"]);
        if (!ea1_opt.has_value()) {
            throw std::runtime_error("Invalid start_address format");
        }
        ea_t ea1 = ea1_opt.value();

        auto ea2_opt = parse_ea(params["end_address"]);
        if (!ea2_opt.has_value()) {
            throw std::runtime_error("Invalid end_address format");
        }
        ea_t ea2 = ea2_opt.value();

        atype_t type = AU_UNK;
        if (params.contains("type") && !params["type"].is_null()) {
            type = static_cast<atype_t>(params["type"].get<int>());
        }

        auto_mark_range(ea1, ea2, type);

        return json{
            {"start_address", format_ea(ea1)},
            {"end_address", format_ea(ea2)},
            {"type", static_cast<int>(type)},
            {"marked", true}
        };
    }

    // Enable/disable auto-analysis
    static json handle_enable_auto(const json &params) {
        bool enable = true;

        if (params.contains("enable") && !params["enable"].is_null()) {
            enable = params["enable"].get<bool>();
        }

        bool previous_state = enable_auto(enable);

        return json{
            {"enable", enable},
            {"previous_state", previous_state},
            {"success", true}
        };
    }

    // Check if auto-analysis is OK
    static json handle_auto_is_ok(const json &params) {
        (void) params; // Unused
        bool is_ok = auto_is_ok();

        return json{
            {"is_ok", is_ok},
            {"note", is_ok ? "Auto-analysis is working normally" : "Auto-analysis has problems"}
        };
    }

    void register_tools(mcp::McpServer &server) {
        // Register get_database_info tool
        mcp::ToolDefinition def;
        def.name = "get_database_info";
        def.description = "Get loaded database info";
        def.input_schema = json{
            {"type", "object"},
            {"properties", json::object()},
            {"required", json::array()}
        };

        server.register_tool(def, get_database_info);

        // save_database
        {
            mcp::ToolDefinition save_def;
            save_def.name = "save_database";
            save_def.description = "Save the current database";
            save_def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "outfile", {
                                {"type", "string"},
                                {"description", "Output file path (optional, defaults to current)"}
                            }
                        },
                        {
                            "flags", {
                                {"type", "number"},
                                {
                                    "description",
                                    "Save flags: DBFL_KILL=1, DBFL_COMP=2, DBFL_BAK=4, DBFL_TEMP=8 (optional)"
                                }
                            }
                        }
                    }
                }
            };
            server.register_tool(save_def, handle_save_database);
        }

        // Note: close_database and open_database registrations removed (idalib-only)

        // auto_wait
        {
            mcp::ToolDefinition wait_def;
            wait_def.name = "auto_wait";
            wait_def.description = "Wait for auto-analysis to complete";
            wait_def.input_schema = json{
                {"type", "object"},
                {"properties", json::object()}
            };
            server.register_tool(wait_def, handle_auto_wait);
        }

        // get_auto_state
        {
            mcp::ToolDefinition state_def;
            state_def.name = "get_auto_state";
            state_def.description = "Get current auto-analysis state";
            state_def.input_schema = json{
                {"type", "object"},
                {"properties", json::object()}
            };
            server.register_tool(state_def, handle_get_auto_state);
        }

        // is_trusted_idb
        {
            mcp::ToolDefinition trust_def;
            trust_def.name = "is_trusted_idb";
            trust_def.description = "Check if database is trusted";
            trust_def.input_schema = json{
                {"type", "object"},
                {"properties", json::object()}
            };
            server.register_tool(trust_def, handle_is_trusted_idb);
        }

        // get_database_flag
        {
            mcp::ToolDefinition get_flag_def;
            get_flag_def.name = "get_database_flag";
            get_flag_def.description = "Get database flag value";
            get_flag_def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "flag", {
                                {"type", "number"},
                                {"description", "Flag to check: DBFL_KILL=1, DBFL_COMP=2, DBFL_BAK=4, DBFL_TEMP=8"}
                            }
                        }
                    }
                },
                {"required", json::array({"flag"})}
            };
            server.register_tool(get_flag_def, handle_get_database_flag);
        }

        // set_database_flag
        {
            mcp::ToolDefinition set_flag_def;
            set_flag_def.name = "set_database_flag";
            set_flag_def.description = "Set or clear database flag";
            set_flag_def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "flag", {
                                {"type", "number"},
                                {"description", "Flag to set: DBFL_KILL=1, DBFL_COMP=2, DBFL_BAK=4, DBFL_TEMP=8"}
                            }
                        },
                        {
                            "value", {
                                {"type", "boolean"},
                                {"description", "Set (true) or clear (false) the flag"}
                            }
                        }
                    }
                },
                {"required", json::array({"flag"})}
            };
            server.register_tool(set_flag_def, handle_set_database_flag);
        }

        // get_path
        {
            mcp::ToolDefinition path_def;
            path_def.name = "get_path";
            path_def.description = "Get various file paths";
            path_def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "path_type", {
                                {"type", "number"},
                                {"description", "Path type: 0=CMD (command line), 1=IDB (database file), 2=ID0"}
                            }
                        }
                    }
                },
                {"required", json::array({"path_type"})}
            };
            server.register_tool(path_def, handle_get_path);
        }

        // Note: make_signatures registration removed (idalib-only)

        // plan_and_wait
        {
            mcp::ToolDefinition plan_def;
            plan_def.name = "plan_and_wait";
            plan_def.description = "Plan analysis and wait for completion";
            plan_def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "start_address", {
                                {"type", "string"},
                                {"description", "Start address in hex"}
                            }
                        },
                        {
                            "end_address", {
                                {"type", "string"},
                                {"description", "End address in hex"}
                            }
                        },
                        {
                            "final_pass", {
                                {"type", "boolean"},
                                {"description", "Perform final pass (default: true)"}
                            }
                        }
                    }
                },
                {"required", json::array({"start_address", "end_address"})}
            };
            server.register_tool(plan_def, handle_plan_and_wait);
        }

        // auto_mark_range
        {
            mcp::ToolDefinition mark_def;
            mark_def.name = "auto_mark_range";
            mark_def.description = "Mark address range for auto-analysis";
            mark_def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "start_address", {
                                {"type", "string"},
                                {"description", "Start address in hex"}
                            }
                        },
                        {
                            "end_address", {
                                {"type", "string"},
                                {"description", "End address in hex"}
                            }
                        },
                        {
                            "type", {
                                {"type", "number"},
                                {"description", "Analysis type (default: AU_UNK=1)"}
                            }
                        }
                    }
                },
                {"required", json::array({"start_address", "end_address"})}
            };
            server.register_tool(mark_def, handle_auto_mark_range);
        }

        // enable_auto
        {
            mcp::ToolDefinition enable_def;
            enable_def.name = "enable_auto";
            enable_def.description = "Enable or disable auto-analysis";
            enable_def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "enable", {
                                {"type", "boolean"},
                                {"description", "Enable (true) or disable (false) auto-analysis"}
                            }
                        }
                    }
                }
            };
            server.register_tool(enable_def, handle_enable_auto);
        }

        // auto_is_ok
        {
            mcp::ToolDefinition ok_def;
            ok_def.name = "auto_is_ok";
            ok_def.description = "Check if auto-analysis is working normally";
            ok_def.input_schema = json{
                {"type", "object"},
                {"properties", json::object()}
            };
            server.register_tool(ok_def, handle_auto_is_ok);
        }
    }
} // namespace ida_mcp::tools::database
