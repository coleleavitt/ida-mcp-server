#include "tools/tools.hpp"
#include <ua.hpp>
#include <nalt.hpp>
#include <funcs.hpp>
#include <xref.hpp>
#include <idp.hpp>
#include <regfinder.hpp>

namespace ida_mcp::tools::indirect_branches {
    namespace {
        // Analyze an indirect branch instruction
        json handle_analyze_indirect_branch(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            // Decode the instruction
            insn_t insn;
            if (decode_insn(&insn, ea) == 0) {
                throw std::runtime_error("No instruction at " + format_ea(ea));
            }

            // Get mnemonic
            qstring mnem;
            print_insn_mnem(&mnem, ea);

            json result;
            result["address"] = format_ea(ea);
            result["mnemonic"] = mnem.c_str();

            // Check if this is an indirect jump using IDA's detection
            bool is_indirect = is_indirect_jump_insn(insn);
            result["is_indirect_jump"] = is_indirect;

            // Check if this is a switch/jump table
            switch_info_t si;
            if (get_switch_info(&si, ea)) {
                // This is a recognized switch table
                result["is_switch"] = true;
                result["switch_type"] = "jump_table";
                result["num_cases"] = si.get_jtable_size();

                // Get jump table address
                if (si.jumps != BADADDR) {
                    result["jump_table_address"] = format_ea(si.jumps);
                }

                // Enumerate switch cases
                json cases = json::array();
                casevec_t casevec;
                if (si.get_jtable_element_size() > 0) {
                    size_t ncases = si.get_jtable_size();
                    for (size_t i = 0; i < ncases && i < 100; i++) {
                        ea_t target = si.jumps + i * si.get_jtable_element_size();

                        // Read the target address from the jump table
                        ea_t case_ea = BADADDR;
                        if (si.get_jtable_element_size() == 4) {
                            uint32 offset = get_dword(target);
                            if (offset != BADADDR) {
                                case_ea = si.jumps + offset;
                            }
                        } else if (si.get_jtable_element_size() == 8) {
                            uint64 offset = get_qword(target);
                            if (offset != BADADDR) {
                                case_ea = offset;
                            }
                        }

                        if (case_ea != BADADDR) {
                            cases.push_back(json{
                                {"case_index", i},
                                {"target", format_ea(case_ea)}
                            });
                        }
                    }
                }
                result["cases"] = cases;
            } else {
                // Not a recognized switch - analyze as generic indirect branch
                result["is_switch"] = false;

                // Analyze the operand
                const op_t &op = insn.ops[0];

                if (op.type == o_reg) {
                    // Register indirect: BR X8, JMP RAX, etc.
                    result["branch_type"] = "register_indirect";
                    result["register"] = op.reg;

                    qstring reg_name;
                    get_reg_name(&reg_name, op.reg, get_dtype_size(op.dtype));
                    result["register_name"] = reg_name.c_str();

                    // Use IDA's register finder to track the value
                    func_t *func = get_func(ea);
                    if (func != nullptr) {
                        // Try to find the register value using reg_finder_t
                        reg_value_info_t reg_value;
                        if (find_reg_value_info(&reg_value, ea, op.reg, 0)) {  // 0 = use default depth from config
                            result["register_tracking"] = {
                                {"state", reg_value.is_unknown() ? "unknown" : (reg_value.is_num() ? "resolved" : "spd")}
                            };

                            // If we resolved to a constant value, that's the target!
                            uval_t target_addr;
                            if (reg_value.get_num(&target_addr)) {
                                result["resolved_target"] = format_ea(target_addr);
                                result["resolution_method"] = "register_tracking";

                                // Check if target is a function
                                func_t *target_func = get_func(target_addr);
                                if (target_func != nullptr) {
                                    qstring target_name;
                                    get_func_name(&target_name, target_func->start_ea);
                                    result["resolved_function"] = target_name.c_str();
                                }
                            }

                            // Get definitions/uses
                            json value_defs = json::array();
                            for (size_t i = 0; i < reg_value.vals_size() && i < 10; i++) {
                                const reg_value_def_t *def = reg_value.vals_begin() + i;
                                json def_json;

                                if (def->def_ea != BADADDR) {
                                    def_json["address"] = format_ea(def->def_ea);

                                    qstring dis;
                                    generate_disasm_line(&dis, def->def_ea, GENDSM_FORCE_CODE);
                                    def_json["disassembly"] = dis.c_str();
                                }

                                value_defs.push_back(def_json);
                            }

                            if (value_defs.size() > 0) {
                                result["value_definitions"] = value_defs;
                            }
                        }
                    }
                } else if (op.type == o_mem || op.type == o_displ || op.type == o_phrase) {
                    // Memory indirect: JMP [table+rax*4], etc.
                    result["branch_type"] = "memory_indirect";

                    if (op.addr != BADADDR) {
                        result["memory_address"] = format_ea(op.addr);
                    }
                } else {
                    result["branch_type"] = "unknown";
                }

                // Check for any xrefs from this instruction
                json targets = json::array();
                xrefblk_t xb;
                for (bool ok = xb.first_from(ea, XREF_FAR); ok && targets.size() < 100; ok = xb.next_from()) {
                    if (xb.iscode) {
                        targets.push_back(format_ea(xb.to));
                    }
                }
                result["known_targets"] = targets;
                result["known_target_count"] = targets.size();
            }

            return result;
        }

        // Trace register backwards to find its source
        json handle_trace_register_usage(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();
            int target_reg = params["register"].get<int>();

            func_t *func = get_func(ea);
            if (func == nullptr) {
                throw std::runtime_error("Address " + format_ea(ea) + " is not in a function");
            }

            json trace = json::array();

            // Scan backwards through the function
            for (ea_t addr = ea; addr != BADADDR && addr >= func->start_ea; addr = prev_head(addr, func->start_ea)) {
                insn_t insn;
                if (decode_insn(&insn, addr) == 0) {
                    continue;
                }

                // Check if this instruction modifies our target register
                bool modifies_reg = false;
                bool reads_reg = false;

                for (int i = 0; i < UA_MAXOP && insn.ops[i].type != o_void; i++) {
                    const op_t &op = insn.ops[i];

                    if (op.type == o_reg && op.reg == target_reg) {
                        // First operand is usually destination, rest are sources
                        if (i == 0) {
                            modifies_reg = true;
                        } else {
                            reads_reg = true;
                        }
                    }
                }

                if (modifies_reg || reads_reg) {
                    qstring dis;
                    generate_disasm_line(&dis, addr, GENDSM_FORCE_CODE);

                    qstring mnem;
                    print_insn_mnem(&mnem, addr);

                    json entry;
                    entry["address"] = format_ea(addr);
                    entry["disassembly"] = dis.c_str();
                    entry["mnemonic"] = mnem.c_str();
                    entry["modifies_register"] = modifies_reg;
                    entry["reads_register"] = reads_reg;

                    // Add operand details
                    json operands = json::array();
                    for (int i = 0; i < UA_MAXOP && insn.ops[i].type != o_void; i++) {
                        qstring op_str;
                        print_operand(&op_str, addr, i);
                        operands.push_back(op_str.c_str());
                    }
                    entry["operands"] = operands;

                    trace.push_back(entry);

                    if (trace.size() >= 50) {
                        break;
                    }
                }
            }

            return json{
                {"address", format_ea(ea)},
                {"register", target_reg},
                {"function", format_ea(func->start_ea)},
                {"trace_count", trace.size()},
                {"trace", trace}
            };
        }
    } // anonymous namespace

    void register_tools(mcp::McpServer &server) {
        // analyze_indirect_branch
        {
            mcp::ToolDefinition def;
            def.name = "analyze_indirect_branch";
            def.description = "Analyze indirect branch instruction";
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
            server.register_tool(def, handle_analyze_indirect_branch);
        }

        // trace_register_usage
        {
            mcp::ToolDefinition def;
            def.name = "trace_register_usage";
            def.description = "Trace register value backwards";
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
                            "register", {
                                {"type", "integer"},
                                {"description", "Register number"}
                            }
                        }
                    }
                },
                {"required", json::array({"address", "register"})}
            };
            server.register_tool(def, handle_trace_register_usage);
        }
    }
} // namespace ida_mcp::tools::indirect_branches
