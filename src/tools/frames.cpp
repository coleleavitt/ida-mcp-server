#include "tools/tools.hpp"
#include <frame.hpp>
#include <funcs.hpp>
#include <typeinf.hpp>

namespace ida_mcp::tools::frames {
    namespace {
        json handle_get_frame_info(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            func_t *func = get_func(ea);
            if (func == nullptr) {
                throw std::runtime_error("No function at " + format_ea(ea));
            }

            // Get frame type info
            tinfo_t frame_tif;
            if (!get_func_frame(&frame_tif, func)) {
                throw std::runtime_error("Failed to get frame info for function at " + format_ea(ea));
            }

            // Get frame parts
            range_t args_range, retaddr_range, savregs_range, lvars_range;
            get_frame_part(&args_range, func, FPC_ARGS);
            get_frame_part(&retaddr_range, func, FPC_RETADDR);
            get_frame_part(&savregs_range, func, FPC_SAVREGS);
            get_frame_part(&lvars_range, func, FPC_LVARS);

            // Get frame size and retsize
            asize_t total_size = get_frame_size(func);
            int retsize = get_frame_retsize(func);

            // Get UDT details (members)
            udt_type_data_t udt;
            json members = json::array();
            if (frame_tif.get_udt_details(&udt)) {
                for (size_t i = 0; i < udt.size(); i++) {
                    const udm_t &member = udt[i];

                    qstring type_str;
                    member.type.print(&type_str);

                    json member_obj;
                    member_obj["name"] = member.name.c_str();
                    member_obj["offset"] = static_cast<uint64_t>(member.offset / 8); // Convert bits to bytes
                    member_obj["size"] = static_cast<uint64_t>(member.size / 8);
                    member_obj["type"] = type_str.c_str();

                    members.push_back(member_obj);
                }
            }

            // Get register variables
            json regvars = json::array();
            regvar_t *rv = find_regvar(func, BADADDR, BADADDR, nullptr, nullptr);
            while (rv != nullptr) {
                json regvar_info = json::object();
                regvar_info["range_start"] = format_ea(rv->start_ea);
                regvar_info["range_end"] = format_ea(rv->end_ea);

                if (rv->canon != nullptr) {
                    regvar_info["canonical_name"] = rv->canon;
                }
                if (rv->user != nullptr) {
                    regvar_info["user_name"] = rv->user;
                }
                if (rv->cmt != nullptr) {
                    regvar_info["comment"] = rv->cmt;
                }

                regvars.push_back(regvar_info);

                // Find next register variable
                rv = find_regvar(func, rv->end_ea, BADADDR, nullptr, nullptr);
                if (rv != nullptr && rv->start_ea < rv->end_ea) {
                    break; // Prevent infinite loop
                }
            }

            json result = json{
                {"address", format_ea(ea)},
                {"total_frame_size", static_cast<uint64_t>(total_size)},
                {"return_address_size", retsize},
                {
                    "parts", {
                        {
                            "args", {
                                {"start", static_cast<int64_t>(args_range.start_ea)},
                                {"end", static_cast<int64_t>(args_range.end_ea)},
                                {"size", static_cast<uint64_t>(args_range.size())}
                            }
                        },
                        {
                            "retaddr", {
                                {"start", static_cast<int64_t>(retaddr_range.start_ea)},
                                {"end", static_cast<int64_t>(retaddr_range.end_ea)},
                                {"size", static_cast<uint64_t>(retaddr_range.size())}
                            }
                        },
                        {
                            "saved_regs", {
                                {"start", static_cast<int64_t>(savregs_range.start_ea)},
                                {"end", static_cast<int64_t>(savregs_range.end_ea)},
                                {"size", static_cast<uint64_t>(savregs_range.size())}
                            }
                        },
                        {
                            "lvars", {
                                {"start", static_cast<int64_t>(lvars_range.start_ea)},
                                {"end", static_cast<int64_t>(lvars_range.end_ea)},
                                {"size", static_cast<uint64_t>(lvars_range.size())}
                            }
                        }
                    }
                },
                {"members", members}
            };

            if (!regvars.empty()) {
                result["register_variables"] = regvars;
                result["register_variable_count"] = regvars.size();
            }

            return result;
        }

        json handle_get_stack_pointer_delta(const json &params) {
            auto func_ea_opt = parse_ea(params["function_address"]);
            if (!func_ea_opt.has_value()) {
                throw std::runtime_error("Invalid function_address format");
            }
            ea_t func_ea = func_ea_opt.value();
            auto query_ea_opt = parse_ea(params["query_address"]);
            if (!query_ea_opt.has_value()) {
                throw std::runtime_error("Invalid query_address format");
            }
            ea_t query_ea = query_ea_opt.value();

            func_t *func = get_func(func_ea);
            if (func == nullptr) {
                throw std::runtime_error("No function at " + format_ea(func_ea));
            }

            // Check if SP analysis is ready
            if ((func->flags & FUNC_SP_READY) == 0) {
                throw std::runtime_error(
                    "SP analysis not complete for function at " + format_ea(func_ea) + ". "
                    "Stack change points are not available. "
                    "This can happen if: (1) Auto-analysis is still running - wait for it to complete, "
                    "(2) The function has non-standard prologue/epilogue, or (3) The function is a thunk/wrapper. "
                    "Try waiting for auto-analysis to complete or use simpler tools like get_function_attributes."
                );
            }

            sval_t spd = get_spd(func, query_ea);
            sval_t effective_spd = get_effective_spd(func, query_ea);
            sval_t sp_delta = get_sp_delta(func, query_ea);

            return json{
                {"function_address", format_ea(func_ea)},
                {"query_address", format_ea(query_ea)},
                {"spd", static_cast<int64_t>(spd)},
                {"effective_spd", static_cast<int64_t>(effective_spd)},
                {"sp_delta", static_cast<int64_t>(sp_delta)},
                {"sp_analysis_ready", true},
                {
                    "description", "Stack pointer tracking at " + format_ea(query_ea) +
                                   ": SPD=" + std::to_string(spd) +
                                   ", Effective SPD=" + std::to_string(effective_spd) +
                                   ", Delta=" + std::to_string(sp_delta)
                }
            };
        }

        json handle_get_stack_variable_name(const json &params) {
            auto func_ea_opt = parse_ea(params["function_address"]);
            if (!func_ea_opt.has_value()) {
                throw std::runtime_error("Invalid function_address format");
            }
            ea_t func_ea = func_ea_opt.value();
            int64_t offset = params["offset"].get<int64_t>();

            func_t *func = get_func(func_ea);
            if (func == nullptr) {
                throw std::runtime_error("No function at " + format_ea(func_ea));
            }

            qstring var_name;
            ssize_t result = build_stkvar_name(&var_name, func, offset);

            if (result < 0 || var_name.empty()) {
                throw std::runtime_error(
                    "No stack variable found at offset " + std::to_string(offset) +
                    " in function " + format_ea(func_ea)
                );
            }

            return json{
                {"function_address", format_ea(func_ea)},
                {"offset", offset},
                {"variable_name", var_name.c_str()}
            };
        }

        json handle_get_frame_part(const json &params) {
            auto func_ea_opt = parse_ea(params["function_address"]);
            if (!func_ea_opt.has_value()) {
                throw std::runtime_error("Invalid function_address format");
            }
            ea_t func_ea = func_ea_opt.value();
            int part = params["part"].get<int>();

            constexpr int MAX_FRAME_PART = 3;
            if (part < 0 || part > MAX_FRAME_PART) {
                throw std::runtime_error("Frame part must be 0 (ARGS), 1 (RETADDR), 2 (SAVREGS), or 3 (LVARS)");
            }

            func_t *func = get_func(func_ea);
            if (func == nullptr) {
                throw std::runtime_error("No function at " + format_ea(func_ea));
            }

            frame_part_t fpc = static_cast<frame_part_t>(part);
            range_t range;
            get_frame_part(&range, func, fpc);

            const char *part_name;
            switch (fpc) {
                case FPC_ARGS: part_name = "ARGS";
                    break;
                case FPC_RETADDR: part_name = "RETADDR";
                    break;
                case FPC_SAVREGS: part_name = "SAVREGS";
                    break;
                case FPC_LVARS: part_name = "LVARS";
                    break;
                default: part_name = "UNKNOWN";
                    break;
            }

            return json{
                {"function_address", format_ea(func_ea)},
                {"part", part},
                {"part_name", part_name},
                {"start_offset", static_cast<int64_t>(range.start_ea)},
                {"end_offset", static_cast<int64_t>(range.end_ea)},
                {"size", static_cast<uint64_t>(range.size())}
            };
        }

        json handle_get_frame_size(const json &params) {
            auto func_ea_opt = parse_ea(params["address"]);
            if (!func_ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t func_ea = func_ea_opt.value();

            func_t *func = get_func(func_ea);
            if (func == nullptr) {
                throw std::runtime_error("No function at " + format_ea(func_ea));
            }

            asize_t size = get_frame_size(func);
            int retsize = get_frame_retsize(func);

            return json{
                {"function_address", format_ea(func_ea)},
                {"total_frame_size", static_cast<uint64_t>(size)},
                {"return_address_size", retsize}
            };
        }
    } // anonymous namespace

    void register_tools(mcp::McpServer &server) {
        // get_frame_info
        {
            mcp::ToolDefinition def;
            def.name = "get_frame_info";
            def.description = "Get stack frame info";
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
            server.register_tool(def, handle_get_frame_info);
        }

        // get_stack_pointer_delta
        {
            mcp::ToolDefinition def;
            def.name = "get_stack_pointer_delta";
            def.description = "Get stack pointer delta";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "function_address", {
                                {"type", "string"},
                                {"description", "Function hex address"}
                            }
                        },
                        {
                            "query_address", {
                                {"type", "string"},
                                {"description", "Query hex address"}
                            }
                        }
                    }
                },
                {"required", json::array({"function_address", "query_address"})}
            };
            server.register_tool(def, handle_get_stack_pointer_delta);
        }

        // get_stack_variable_name
        {
            mcp::ToolDefinition def;
            def.name = "get_stack_variable_name";
            def.description = "Get stack variable name";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "function_address", {
                                {"type", "string"},
                                {"description", "Function hex address"}
                            }
                        },
                        {
                            "offset", {
                                {"type", "number"},
                                {"description", "Stack offset"}
                            }
                        }
                    }
                },
                {"required", json::array({"function_address", "offset"})}
            };
            server.register_tool(def, handle_get_stack_variable_name);
        }

        // get_frame_part
        {
            mcp::ToolDefinition def;
            def.name = "get_frame_part";
            def.description = "Get frame part info";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "function_address", {
                                {"type", "string"},
                                {"description", "Function hex address"}
                            }
                        },
                        {
                            "part", {
                                {"type", "number"},
                                {"description", "Frame part ID"}
                            }
                        }
                    }
                },
                {"required", json::array({"function_address", "part"})}
            };
            server.register_tool(def, handle_get_frame_part);
        }

        // get_frame_size
        {
            mcp::ToolDefinition def;
            def.name = "get_frame_size";
            def.description = "Get frame size in bytes";
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
            server.register_tool(def, handle_get_frame_size);
        }
    }
} // namespace ida_mcp::tools::frames
