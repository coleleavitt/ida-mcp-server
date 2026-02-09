#include "tools/tools.hpp"
#include <dbg.hpp>

namespace ida_mcp::tools::debugger {
    namespace {
        // Check if debugger is currently active
        static json is_debugger_active(const json & /* params */) {
            bool active = is_debugger_on();

            return json{
                {"active", active},
                {"process_state", get_process_state()}
            };
        }

        // Get current process state and debugging status
        static json get_debug_status(const json & /* params */) {
            bool debugger_on = is_debugger_on();
            int proc_state = get_process_state();

            json result;
            result["debugger_active"] = debugger_on;
            result["process_state"] = proc_state;
            result["debugger_busy"] = is_debugger_busy();

            // Process state descriptions
            const char *state_desc;
            switch (proc_state) {
                case DSTATE_SUSP: state_desc = "Suspended";
                    break;
                case DSTATE_NOTASK: state_desc = "No Process";
                    break;
                case DSTATE_RUN: state_desc = "Running";
                    break;
                default: state_desc = "Unknown";
                    break;
            }
            result["state_description"] = state_desc;

            if (debugger_on) {
                result["thread_count"] = get_thread_qty();
                result["current_thread"] = get_current_thread();
            }

            return result;
        }

        // List all threads in debugged process
        static json list_threads(const json & /* params */) {
            if (!is_debugger_on()) {
                throw std::runtime_error("Debugger is not active");
            }

            int qty = get_thread_qty();
            thid_t current = get_current_thread();

            json threads = json::array();
            for (int i = 0; i < qty; i++) {
                thid_t tid = getn_thread(i);
                const char *name = getn_thread_name(i);

                json thread_info;
                thread_info["index"] = i;
                thread_info["thread_id"] = tid;
                thread_info["name"] = name ? name : "";
                thread_info["is_current"] = (tid == current);

                threads.push_back(thread_info);
            }

            return json{
                {"thread_count", qty},
                {"current_thread", current},
                {"threads", threads}
            };
        }

        // Get register value
        static json get_register_value(const json &params) {
            if (!is_debugger_on()) {
                throw std::runtime_error("Debugger is not active");
            }

            std::string regname = params["register"].get<std::string>();

            regval_t regval;
            if (!get_reg_val(regname.c_str(), &regval)) {
                throw std::runtime_error("Failed to read register: " + regname);
            }

            json result;
            result["register"] = regname;
            result["type"] = regval.rvtype;

            // Convert register value based on type
            switch (regval.rvtype) {
                case RVT_INT:
                    result["value"] = static_cast<uint64_t>(regval.ival);
                    result["value_hex"] = format_ea(regval.ival);
                    break;
                case RVT_FLOAT:
                    // Float registers - just note it's a float type
                    result["value_type"] = "float";
                    break;
                default:
                    result["value"] = "unsupported_type";
                    break;
            }

            return result;
        }

        // List all breakpoints
        static json list_breakpoints(const json & /* params */) {
            int qty = get_bpt_qty();

            json breakpoints = json::array();
            for (int i = 0; i < qty; i++) {
                bpt_t bpt;
                if (getn_bpt(i, &bpt)) {
                    json bpt_info;
                    bpt_info["index"] = i;
                    bpt_info["address"] = format_ea(bpt.ea);
                    bpt_info["size"] = bpt.size;
                    bpt_info["enabled"] = ((bpt.flags & BPT_ENABLED) != 0);

                    // Breakpoint type
                    const char *type_str;
                    switch (bpt.type) {
                        case BPT_SOFT: type_str = "Software";
                            break;
                        case BPT_EXEC: type_str = "Hardware_Execute";
                            break;
                        case BPT_WRITE: type_str = "Hardware_Write";
                            break;
                        case BPT_RDWR: type_str = "Hardware_ReadWrite";
                            break;
                        default: type_str = "Unknown";
                            break;
                    }
                    bpt_info["type"] = type_str;

                    breakpoints.push_back(bpt_info);
                }
            }

            return json{
                {"breakpoint_count", qty},
                {"breakpoints", breakpoints}
            };
        }

        // Get breakpoint at specific address
        static json get_breakpoint(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            bpt_t bpt;
            if (!get_bpt(ea, &bpt)) {
                return json{
                    {"exists", false},
                    {"address", format_ea(ea)}
                };
            }

            json result;
            result["exists"] = true;
            result["address"] = format_ea(bpt.ea);
            result["size"] = bpt.size;
            result["enabled"] = ((bpt.flags & BPT_ENABLED) != 0);

            // Breakpoint type
            const char *type_str;
            switch (bpt.type) {
                case BPT_SOFT: type_str = "Software";
                    break;
                case BPT_EXEC: type_str = "Hardware_Execute";
                    break;
                case BPT_WRITE: type_str = "Hardware_Write";
                    break;
                case BPT_RDWR: type_str = "Hardware_ReadWrite";
                    break;
                default: type_str = "Unknown";
                    break;
            }
            result["type"] = type_str;

            return result;
        }

        // List loaded modules in debugged process
        static json list_modules(const json & /* params */) {
            if (!is_debugger_on()) {
                throw std::runtime_error("Debugger is not active");
            }

            json modules = json::array();
            modinfo_t modinfo;

            if (get_first_module(&modinfo)) {
                do {
                    json mod;
                    mod["name"] = modinfo.name.c_str();
                    mod["base_address"] = format_ea(modinfo.base);
                    mod["size"] = modinfo.size;
                    mod["rebase_to"] = format_ea(modinfo.rebase_to);

                    modules.push_back(mod);
                } while (get_next_module(&modinfo));
            }

            return json{
                {"module_count", modules.size()},
                {"modules", modules}
            };
        }

        // Check if address is in debugger memory space
        static json is_debug_memory(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            bool is_dbg_mem = is_debugger_memory(ea);

            json result;
            result["address"] = format_ea(ea);
            result["is_debugger_memory"] = is_dbg_mem;

            // Try to read a byte if it's debugger memory
            if (is_dbg_mem) {
                uint32 byte_val;
                if (get_dbg_byte(&byte_val, ea)) {
                    result["readable"] = true;
                    result["byte_value"] = byte_val;
                } else {
                    result["readable"] = false;
                }
            }

            return result;
        }

        // Start or resume debugging
        static json start_debug_process(const json &params) {
            std::string path;
            std::string args;
            std::string sdir;

            if (params.contains("path")) {
                path = params["path"].get<std::string>();
            }

            if (params.contains("args")) {
                args = params["args"].get<std::string>();
            }

            if (params.contains("start_dir")) {
                sdir = params["start_dir"].get<std::string>();
            }

            // Start the process
            bool success = start_process(
                path.empty() ? nullptr : path.c_str(),
                args.empty() ? nullptr : args.c_str(),
                sdir.empty() ? nullptr : sdir.c_str()
            );

            json result;
            result["success"] = success;

            if (success) {
                result["debugger_active"] = is_debugger_on();
                result["process_state"] = get_process_state();
            }

            return result;
        }

        // Continue execution
        static json continue_process_exec(const json & /* params */) {
            if (!is_debugger_on()) {
                throw std::runtime_error("Debugger is not active");
            }

            bool success = continue_process();

            return json{
                {"success", success},
                {"process_state", get_process_state()}
            };
        }

        // Suspend process execution
        static json suspend_process_exec(const json & /* params */) {
            if (!is_debugger_on()) {
                throw std::runtime_error("Debugger is not active");
            }

            bool success = suspend_process();

            return json{
                {"success", success},
                {"process_state", get_process_state()}
            };
        }

        // Step into (execute one instruction, entering calls)
        static json step_into_exec(const json & /* params */) {
            if (!is_debugger_on()) {
                throw std::runtime_error("Debugger is not active");
            }

            bool success = step_into();

            return json{
                {"success", success},
                {"process_state", get_process_state()}
            };
        }

        // Step over (execute one instruction, stepping over calls)
        static json step_over_exec(const json & /* params */) {
            if (!is_debugger_on()) {
                throw std::runtime_error("Debugger is not active");
            }

            bool success = step_over();

            return json{
                {"success", success},
                {"process_state", get_process_state()}
            };
        }

        // Step until return
        static json step_until_ret_exec(const json & /* params */) {
            if (!is_debugger_on()) {
                throw std::runtime_error("Debugger is not active");
            }

            bool success = step_until_ret();

            return json{
                {"success", success},
                {"process_state", get_process_state()}
            };
        }

        // Run to specific address
        static json run_to_address(const json &params) {
            if (!is_debugger_on()) {
                throw std::runtime_error("Debugger is not active");
            }

            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            bool success = run_to(ea);

            return json{
                {"success", success},
                {"target_address", format_ea(ea)},
                {"process_state", get_process_state()}
            };
        }

        // Exit the debugged process
        static json exit_debug_process(const json & /* params */) {
            if (!is_debugger_on()) {
                throw std::runtime_error("Debugger is not active");
            }

            bool success = exit_process();

            return json{
                {"success", success},
                {"debugger_active", is_debugger_on()}
            };
        }

        // Add a breakpoint
        static json add_breakpoint(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            bpttype_t bpt_type = BPT_SOFT; // Default to software
            asize_t size = 0; // Default size

            // Parse breakpoint type if provided
            if (params.contains("type")) {
                std::string type_str = params["type"].get<std::string>();
                if (type_str == "software" || type_str == "Software") {
                    bpt_type = BPT_SOFT;
                } else if (type_str == "hardware_exec" || type_str == "Hardware_Execute") {
                    bpt_type = BPT_EXEC;
                } else if (type_str == "hardware_write" || type_str == "Hardware_Write") {
                    bpt_type = BPT_WRITE;
                } else if (type_str == "hardware_readwrite" || type_str == "Hardware_ReadWrite") {
                    bpt_type = BPT_RDWR;
                }
            }

            bool success = add_bpt(ea, size, bpt_type);

            json result;
            result["success"] = success;
            result["address"] = format_ea(ea);

            if (success) {
                const char *type_str;
                switch (bpt_type) {
                    case BPT_SOFT: type_str = "Software";
                        break;
                    case BPT_EXEC: type_str = "Hardware_Execute";
                        break;
                    case BPT_WRITE: type_str = "Hardware_Write";
                        break;
                    case BPT_RDWR: type_str = "Hardware_ReadWrite";
                        break;
                    default: type_str = "Unknown";
                        break;
                }
                result["type"] = type_str;
            }

            return result;
        }

        // Delete a breakpoint
        static json delete_breakpoint(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            bool success = del_bpt(ea);

            return json{
                {"success", success},
                {"address", format_ea(ea)}
            };
        }

        // Enable a breakpoint
        static json enable_breakpoint(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            bool success = enable_bpt(ea, true);

            return json{
                {"success", success},
                {"address", format_ea(ea)},
                {"enabled", true}
            };
        }

        // Disable a breakpoint
        static json disable_breakpoint(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            bool success = enable_bpt(ea, false);

            return json{
                {"success", success},
                {"address", format_ea(ea)},
                {"enabled", false}
            };
        }

        // Switch to a different thread
        static json select_debug_thread(const json &params) {
            if (!is_debugger_on()) {
                throw std::runtime_error("Debugger is not active");
            }

            thid_t tid = params["thread_id"].get<thid_t>();

            bool success = select_thread(tid);

            return json{
                {"success", success},
                {"thread_id", tid},
                {"current_thread", get_current_thread()}
            };
        }
    } // anonymous namespace

    void register_tools(mcp::McpServer &server) {
        // is_debugger_active
        {
            mcp::ToolDefinition def;
            def.name = "is_debugger_active";
            def.description = "Check if debugger is active";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {}},
                {"required", json::array()}
            };
            server.register_tool(def, is_debugger_active);
        }

        // get_debug_status
        {
            mcp::ToolDefinition def;
            def.name = "get_debug_status";
            def.description = "Get debugger status";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {}},
                {"required", json::array()}
            };
            server.register_tool(def, get_debug_status);
        }

        // list_threads
        {
            mcp::ToolDefinition def;
            def.name = "list_threads";
            def.description = "List threads in process";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {}},
                {"required", json::array()}
            };
            server.register_tool(def, list_threads);
        }

        // get_register_value
        {
            mcp::ToolDefinition def;
            def.name = "get_register_value";
            def.description = "Read CPU register value";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "register", {
                                {"type", "string"},
                                {"description", "Register name"}
                            }
                        }
                    }
                },
                {"required", json::array({"register"})}
            };
            server.register_tool(def, get_register_value);
        }

        // list_breakpoints
        {
            mcp::ToolDefinition def;
            def.name = "list_breakpoints";
            def.description = "List all breakpoints";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {}},
                {"required", json::array()}
            };
            server.register_tool(def, list_breakpoints);
        }

        // get_breakpoint
        {
            mcp::ToolDefinition def;
            def.name = "get_breakpoint";
            def.description = "Get breakpoint at address";
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
            server.register_tool(def, get_breakpoint);
        }

        // list_modules
        {
            mcp::ToolDefinition def;
            def.name = "list_modules";
            def.description = "List loaded modules/DLLs";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {}},
                {"required", json::array()}
            };
            server.register_tool(def, list_modules);
        }

        // is_debug_memory
        {
            mcp::ToolDefinition def;
            def.name = "is_debug_memory";
            def.description = "Check if address in debug memory";
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
            server.register_tool(def, is_debug_memory);
        }

        // start_debug_process
        {
            mcp::ToolDefinition def;
            def.name = "start_debug_process";
            def.description = "Start debugging process";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "path", {
                                {"type", "string"},
                                {"description", "Executable path"}
                            }
                        },
                        {
                            "args", {
                                {"type", "string"},
                                {"description", "Command args"}
                            }
                        },
                        {
                            "start_dir", {
                                {"type", "string"},
                                {"description", "Start directory"}
                            }
                        }
                    }
                },
                {"required", json::array()}
            };
            server.register_tool(def, start_debug_process);
        }

        // continue_process
        {
            mcp::ToolDefinition def;
            def.name = "continue_process";
            def.description = "Continue process execution";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {}},
                {"required", json::array()}
            };
            server.register_tool(def, continue_process_exec);
        }

        // suspend_process
        {
            mcp::ToolDefinition def;
            def.name = "suspend_process";
            def.description = "Suspend process execution";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {}},
                {"required", json::array()}
            };
            server.register_tool(def, suspend_process_exec);
        }

        // step_into
        {
            mcp::ToolDefinition def;
            def.name = "step_into";
            def.description = "Step into instruction";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {}},
                {"required", json::array()}
            };
            server.register_tool(def, step_into_exec);
        }

        // step_over
        {
            mcp::ToolDefinition def;
            def.name = "step_over";
            def.description = "Step over instruction";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {}},
                {"required", json::array()}
            };
            server.register_tool(def, step_over_exec);
        }

        // step_until_ret
        {
            mcp::ToolDefinition def;
            def.name = "step_until_ret";
            def.description = "Execute until return";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {}},
                {"required", json::array()}
            };
            server.register_tool(def, step_until_ret_exec);
        }

        // run_to
        {
            mcp::ToolDefinition def;
            def.name = "run_to";
            def.description = "Run to address";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "address", {
                                {"type", "string"},
                                {"description", "Target hex address"}
                            }
                        }
                    }
                },
                {"required", json::array({"address"})}
            };
            server.register_tool(def, run_to_address);
        }

        // exit_process
        {
            mcp::ToolDefinition def;
            def.name = "exit_process";
            def.description = "Terminate debugged process";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {}},
                {"required", json::array()}
            };
            server.register_tool(def, exit_debug_process);
        }

        // add_breakpoint
        {
            mcp::ToolDefinition def;
            def.name = "add_breakpoint";
            def.description = "Add breakpoint at address";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "address", {
                                {"type", "string"},
                                {"description", "Hex address"}
                            }
                        },
                        {
                            "type", {
                                {"type", "string"},
                                {"description", "Breakpoint type"},
                                {
                                    "enum",
                                    json::array({"software", "hardware_exec", "hardware_write", "hardware_readwrite"})
                                }
                            }
                        }
                    }
                },
                {"required", json::array({"address"})}
            };
            server.register_tool(def, add_breakpoint);
        }

        // delete_breakpoint
        {
            mcp::ToolDefinition def;
            def.name = "delete_breakpoint";
            def.description = "Remove breakpoint";
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
            server.register_tool(def, delete_breakpoint);
        }

        // enable_breakpoint
        {
            mcp::ToolDefinition def;
            def.name = "enable_breakpoint";
            def.description = "Enable breakpoint";
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
            server.register_tool(def, enable_breakpoint);
        }

        // disable_breakpoint
        {
            mcp::ToolDefinition def;
            def.name = "disable_breakpoint";
            def.description = "Disable breakpoint";
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
            server.register_tool(def, disable_breakpoint);
        }

        // select_thread
        {
            mcp::ToolDefinition def;
            def.name = "select_thread";
            def.description = "Switch to different thread";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "thread_id", {
                                {"type", "integer"},
                                {"description", "Thread ID to select"}
                            }
                        }
                    }
                },
                {"required", json::array({"thread_id"})}
            };
            server.register_tool(def, select_debug_thread);
        }
    }
} // namespace ida_mcp::tools::debugger
