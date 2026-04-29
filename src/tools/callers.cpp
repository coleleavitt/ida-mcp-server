#include "tools/tools.hpp"
#include <xref.hpp>
#include <funcs.hpp>
#include <segment.hpp>
#include <ua.hpp>
#include <regfinder.hpp>
#include <set>

namespace ida_mcp::tools::callers {
    namespace {
        const char *xref_type_to_string(uchar type) {
            switch (type) {
                case fl_CF: return "Call_Far";
                case fl_CN: return "Call_Near";
                case fl_JF: return "Jump_Far";
                case fl_JN: return "Jump_Near";
                default: return "Code_Unknown";
            }
        }

        // Helper to check if address is in exception handler segment
        bool is_exception_handler_segment(ea_t ea) {
            segment_t *seg = getseg(ea);
            if (seg == nullptr) {
                return false;
            }

            qstring seg_name;
            get_segm_name(&seg_name, seg);

            const char *name = seg_name.c_str();
            return strstr(name, ".pdata") != nullptr ||
                   strstr(name, ".xdata") != nullptr ||
                   strstr(name, "except") != nullptr;
        }

        json handle_get_callers(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            json callers = json::array();
            std::set<ea_t> seen_funcs;

            // PHASE 1: Direct code xrefs (direct calls/jumps)
            xrefblk_t xb;
            for (bool ok = xb.first_to(ea, XREF_FAR); ok; ok = xb.next_to()) {
                // Skip data references
                if (xb.iscode == 0) {
                    continue;
                }

                // Get function containing the xref
                func_t *func = get_func(xb.from);
                if (func == nullptr) {
                    continue;
                }

                ea_t func_start = func->start_ea;

                // Skip duplicates (same function calling multiple times)
                if (seen_funcs.find(func_start) != seen_funcs.end()) {
                    continue;
                }
                seen_funcs.insert(func_start);

                // Get function name
                qstring name;
                get_func_name(&name, func_start);

                // Detect tail calls (jumps to different function)
                bool is_tail_call = false;
                if (xb.type == fl_JF || xb.type == fl_JN) {
                    func_t *target_func = get_func(xb.to);
                    is_tail_call = (target_func != nullptr && target_func != func);
                }

                const char *xref_type_str = xref_type_to_string(xb.type);

                callers.push_back(json{
                    {"address", format_ea(func_start)},
                    {"call_site", format_ea(xb.from)},
                    {"name", name.c_str()},
                    {"type", is_tail_call ? "Tail_Call" : xref_type_str},
                    {"indirect", false},
                    {"tail_call", is_tail_call}
                });
            }

            // PHASE 2: Indirect calls via function pointers
            // Find DATA xrefs to this address (function pointer references)
            xrefblk_t xb_data;
            for (bool ok = xb_data.first_to(ea, XREF_DATA); ok; ok = xb_data.next_to()) {
                ea_t data_ref = xb_data.from;

                // Check if this data reference is in an exception handler table
                bool is_exception_handler = is_exception_handler_segment(data_ref);

                // This is a location that contains a pointer to our function
                // Now find code that references this pointer location
                xrefblk_t xb_code;
                bool has_code_xref = false;

                for (bool ok_code = xb_code.first_to(data_ref, XREF_FAR); ok_code; ok_code = xb_code.next_to()) {
                    if (xb_code.iscode == 0) {
                        continue;
                    }

                    has_code_xref = true;
                    func_t *func = get_func(xb_code.from);
                    if (func == nullptr) {
                        continue;
                    }

                    ea_t func_start = func->start_ea;
                    if (seen_funcs.find(func_start) != seen_funcs.end()) {
                        continue;
                    }
                    seen_funcs.insert(func_start);

                    qstring name;
                    get_func_name(&name, func_start);

                    json caller_json;
                    caller_json["address"] = format_ea(func_start);
                    caller_json["call_site"] = format_ea(xb_code.from);
                    caller_json["via_pointer"] = format_ea(data_ref);
                    caller_json["name"] = name.c_str();
                    caller_json["indirect"] = true;

                    if (is_exception_handler) {
                        caller_json["type"] = "Exception_Handler_Ref";
                        caller_json["exception_handler"] = true;
                    } else {
                        caller_json["type"] = "Indirect_Call";
                    }

                    callers.push_back(caller_json);
                }

                // If no code xrefs but it's in exception handler table, record it specially
                if (!has_code_xref && is_exception_handler) {
                    json handler_json;
                    handler_json["address"] = format_ea(ea);
                    handler_json["call_site"] = "exception_handler";
                    handler_json["via_pointer"] = format_ea(data_ref);
                    handler_json["name"] = "<exception handler>";
                    handler_json["type"] = "Exception_Handler";
                    handler_json["indirect"] = true;
                    handler_json["exception_handler"] = true;

                    callers.push_back(handler_json);
                }
            }

            return json{
                {"address", format_ea(ea)},
                {"caller_count", callers.size()},
                {"callers", callers}
            };
        }

        json handle_get_callees(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            func_t *func = get_func(ea);
            if (func == nullptr) {
                throw std::runtime_error("No function at " + format_ea(ea));
            }

            json callees = json::array();
            std::set<ea_t> seen_targets;
            std::set<ea_t> indirect_sites; // Track indirect call sites

            ea_t func_ea = func->start_ea;
            ea_t end_ea = func->end_ea;

            // PHASE 1: Direct calls/jumps via xrefs
            for (ea_t addr = func_ea; addr < end_ea; addr = next_head(addr, end_ea)) {
                xrefblk_t xb;
                for (bool ok = xb.first_from(addr, XREF_FAR); ok; ok = xb.next_from()) {
                    // Skip data references
                    if (xb.iscode == 0) {
                        continue;
                    }

                    // Skip non-call/jump xrefs (like ordinary flow)
                    if (xb.type != fl_CF && xb.type != fl_CN &&
                        xb.type != fl_JF && xb.type != fl_JN) {
                        continue;
                    }

                    ea_t target = xb.to;

                    // Skip duplicates
                    if (seen_targets.find(target) != seen_targets.end()) {
                        continue;
                    }
                    seen_targets.insert(target);

                    // Get target function
                    func_t *target_func = get_func(target);
                    qstring target_name;
                    ea_t final_target = target;
                    bool is_thunk = false;

                    if (target_func != nullptr) {
                        // Check if this is a thunk - resolve to actual target
                        ea_t thunk_target_ptr = BADADDR;
                        ea_t thunk_target = calc_thunk_func_target(target_func, &thunk_target_ptr);

                        if (thunk_target != BADADDR && thunk_target != target) {
                            // This is a thunk - update target
                            is_thunk = true;
                            final_target = thunk_target;

                            func_t *real_func = get_func(thunk_target);
                            if (real_func != nullptr) {
                                get_func_name(&target_name, real_func->start_ea);
                            }
                        } else {
                            get_func_name(&target_name, target_func->start_ea);
                        }
                    } else {
                        target_name = "<external>";
                    }

                    const char *xref_type_str = xref_type_to_string(xb.type);

                    json callee_json;
                    callee_json["address"] = format_ea(final_target);
                    callee_json["call_site"] = format_ea(addr);
                    callee_json["name"] = target_name.c_str();
                    callee_json["type"] = xref_type_str;

                    if (is_thunk) {
                        callee_json["is_thunk"] = true;
                        callee_json["thunk_address"] = format_ea(target);
                    }

                    callees.push_back(callee_json);
                }
            }

            // PHASE 2: Indirect/computed calls (no xref targets)
            // Scan for call/jump instructions without xrefs - these are indirect/virtual calls
            for (ea_t addr = func_ea; addr < end_ea; addr = next_head(addr, end_ea)) {
                // Decode instruction
                insn_t insn;
                if (decode_insn(&insn, addr) == 0) {
                    continue;
                }

                // Get mnemonic
                qstring mnem;
                print_insn_mnem(&mnem, addr);

                // Convert to uppercase for comparison
                char mnem_upper[16] = {0};
                qstrncpy(mnem_upper, mnem.c_str(), sizeof(mnem_upper));
                for (int i = 0; mnem_upper[i]; i++) {
                    mnem_upper[i] = toupper(mnem_upper[i]);
                }

                // Check for call/jump instructions (x86: call/jmp, ARM64: BL/BLR/B/BR)
                bool is_call = (strcmp(mnem_upper, "CALL") == 0 || strcmp(mnem_upper, "BL") == 0 || strcmp(
                                    mnem_upper, "BLR") == 0);
                bool is_jump = (strcmp(mnem_upper, "JMP") == 0 || strcmp(mnem_upper, "B") == 0 || strcmp(
                                    mnem_upper, "BR") == 0);

                if (!is_call && !is_jump) {
                    continue;
                }

                // Check if this instruction has a code xref (direct target)
                xrefblk_t xb_check;
                bool has_xref = xb_check.first_from(addr, XREF_FAR);
                if (has_xref && xb_check.iscode) {
                    // Has direct xref - already handled in phase 1
                    continue;
                }

                // This is an indirect call/jump - analyze the operand
                const op_t &op = insn.ops[0];

                const char *call_type;
                bool is_virtual = false;

                // Check operand type to classify the indirect call
                if (op.type == o_mem || op.type == o_displ || op.type == o_phrase) {
                    // Memory dereference - likely vtable call
                    if (is_call) {
                        call_type = "Virtual_Call";
                        is_virtual = true;
                    } else {
                        call_type = "Virtual_Jump";
                        is_virtual = true;
                    }
                } else if (op.type == o_reg) {
                    // Register-indirect (e.g., call rax, BR X8, BLR X9)
                    if (is_call) {
                        call_type = "Indirect_Call_Register";
                    } else {
                        call_type = "Indirect_Jump_Register";
                    }
                } else {
                    // Other indirect type
                    if (is_call) {
                        call_type = "Indirect_Call";
                    } else {
                        call_type = "Indirect_Jump";
                    }
                }

                json call_json;
                call_json["address"] = "unknown";
                call_json["call_site"] = format_ea(addr);
                call_json["name"] = is_virtual ? "<virtual>" : "<computed/indirect>";
                call_json["type"] = call_type;
                call_json["indirect"] = true;
                call_json["mnemonic"] = mnem.c_str();

                // Try to resolve indirect targets using register tracking
                if (op.type == o_reg) {
                    // Register-indirect call - try to track register value
                    reg_value_info_t reg_value;
                    if (find_reg_value_info(&reg_value, addr, op.reg, 0)) {
                        // 0 = use default depth from config
                        uval_t target_addr;
                        if (reg_value.get_num(&target_addr)) {
                            // Resolved to a constant - this is the target!
                            call_json["address"] = format_ea(target_addr);
                            call_json["resolved_by"] = "register_tracking";

                            func_t *target_func = get_func(target_addr);
                            if (target_func != nullptr) {
                                qstring target_name;
                                get_func_name(&target_name, target_func->start_ea);
                                call_json["name"] = target_name.c_str();
                                call_json["warning"] = "Resolved via register tracking";
                            }
                        }
                    }
                }

                if (is_virtual) {
                    call_json["virtual_call"] = true;
                    if (call_json["address"] == "unknown") {
                        call_json["warning"] = "C++ virtual call through vtable - target unknown";
                    }
                } else if (call_json["address"] == "unknown") {
                    call_json["warning"] = "Computed/register-indirect - static analysis cannot determine target";
                }

                callees.push_back(call_json);
            }

            return json{
                {"function", format_ea(func_ea)},
                {"callee_count", callees.size()},
                {"callees", callees}
            };
        }
    } // anonymous namespace

    void register_tools(mcp::McpServer &server) {
        // get_callers
        {
            mcp::ToolDefinition def;
            def.name = "get_callers";
            def.description = "Get all callers of function";
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
            server.register_tool(def, handle_get_callers);
        }

        // get_callees
        {
            mcp::ToolDefinition def;
            def.name = "get_callees";
            def.description = "Get all callees of function";
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
            server.register_tool(def, handle_get_callees);
        }
    }
} // namespace ida_mcp::tools::callers
