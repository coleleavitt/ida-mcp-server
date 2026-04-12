#include "tools/tools.hpp"
#include <ua.hpp>
#include <nalt.hpp>
#include <funcs.hpp>
#include <xref.hpp>
#include <idp.hpp>
#include <regfinder.hpp>

// ARM64 PAC constants (from RE of arm.so processor module)
#define AUX_PAC        0x10000
#define PAC_KEYMASK    0x07
#define PAC_KEY_IA     0x00
#define PAC_KEY_IB     0x01
#define PAC_KEY_DA     0x02
#define PAC_KEY_DB     0x03
#define PAC_KEY_GA     0x04
#define PAC_ADRMASK    (3<<3)
#define PAC_ADR_GPR    (0<<3)
#define PAC_ADR_X17    (1<<3)
#define PAC_ADR_X30    (2<<3)
#define PAC_MODMASK    (3<<5)
#define PAC_MOD_GPR    (0<<5)
#define PAC_MOD_ZR     (1<<5)
#define PAC_MOD_X16    (2<<5)
#define PAC_MOD_SP     (3<<5)

// ARM64 instruction types (from RE of arm.so check_for_table_jump dispatcher)
#define ARM_ITYPE_BR     4
#define ARM_ITYPE_BLR    14
#define ARM_ITYPE_BLRA   23
#define ARM_ITYPE_LDR_PC 31
#define ARM_ITYPE_BRAB   41
#define ARM_ITYPE_THUNK  46
#define ARM_ITYPE_TBB    274
#define ARM_ITYPE_TBH    275
#define ARM_ITYPE_BRAB2  470

namespace ida_mcp::tools::indirect_branches {
    namespace {
        const char *get_pac_key_str(int key) {
            switch (key & PAC_KEYMASK) {
                case PAC_KEY_IA: return "IA";
                case PAC_KEY_IB: return "IB";
                case PAC_KEY_DA: return "DA";
                case PAC_KEY_DB: return "DB";
                case PAC_KEY_GA: return "GA";
                default: return "unknown";
            }
        }

        const char *get_pac_addr_str(int flags) {
            switch (flags & PAC_ADRMASK) {
                case PAC_ADR_GPR: return "gpr";
                case PAC_ADR_X17: return "x17";
                case PAC_ADR_X30: return "lr";
                default: return "unknown";
            }
        }

        const char *get_pac_mod_str(int flags) {
            switch (flags & PAC_MODMASK) {
                case PAC_MOD_GPR: return "gpr";
                case PAC_MOD_ZR: return "zero";
                case PAC_MOD_X16: return "x16";
                case PAC_MOD_SP: return "sp";
                default: return "unknown";
            }
        }

        const char *classify_arm_branch(int itype) {
            switch (itype) {
                case ARM_ITYPE_BR: return "BR";
                case ARM_ITYPE_BLR: return "BLR";
                case ARM_ITYPE_BLRA: return "BLRAA/BLRAB";
                case ARM_ITYPE_LDR_PC: return "LDR_PC";
                case ARM_ITYPE_BRAB: return "BRAA/BRAB";
                case ARM_ITYPE_THUNK: return "thunk";
                case ARM_ITYPE_TBB: return "TBB";
                case ARM_ITYPE_TBH: return "TBH";
                case ARM_ITYPE_BRAB2: return "BRAA/BRAB_v2";
                default: return nullptr;
            }
        }

        json handle_analyze_indirect_branch(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address format");
            ea_t ea = ea_opt.value();

            insn_t insn;
            if (decode_insn(&insn, ea) == 0)
                throw std::runtime_error("No instruction at " + format_ea(ea));

            qstring mnem;
            print_insn_mnem(&mnem, ea);

            json result;
            result["address"] = format_ea(ea);
            result["mnemonic"] = mnem.c_str();
            result["itype"] = insn.itype;

            bool is_indirect = is_indirect_jump_insn(insn);
            result["is_indirect_jump"] = is_indirect;

            // PAC detection (from RE of arm.so sub_1D540)
            bool is_pac = (insn.auxpref & AUX_PAC) != 0;
            if (is_pac) {
                int pac_flags = insn.insnpref;
                result["pac"] = json{
                    {"authenticated", true},
                    {"key", get_pac_key_str(pac_flags)},
                    {"address_reg", get_pac_addr_str(pac_flags)},
                    {"modifier", get_pac_mod_str(pac_flags)},
                    {"raw_flags", pac_flags}
                };
            }

            // ARM64 instruction type classification (from RE of arm.so sub_732C0)
            const char *arm_class = classify_arm_branch(insn.itype);
            if (arm_class != nullptr)
                result["arm_branch_class"] = arm_class;

            // Thunk resolution via calc_thunk_func_target
            if (insn.itype == ARM_ITYPE_THUNK || is_indirect) {
                ea_t thunk_target = BADADDR;
                func_t *func = get_func(ea);
                if (func != nullptr) {
                    ea_t fptr = BADADDR;
                    thunk_target = calc_thunk_func_target(func, &fptr);
                    if (thunk_target != BADADDR) {
                        result["thunk_target"] = format_ea(thunk_target);
                        if (fptr != BADADDR)
                            result["thunk_fptr"] = format_ea(fptr);
                        qstring tname;
                        get_func_name(&tname, thunk_target);
                        if (!tname.empty())
                            result["thunk_target_name"] = tname.c_str();
                    }
                }
            }

            // Switch/jump table analysis
            switch_info_t si;
            if (get_switch_info(&si, ea)) {
                result["is_switch"] = true;
                result["num_cases"] = si.get_jtable_size();

                if (si.jumps != BADADDR)
                    result["jump_table_address"] = format_ea(si.jumps);
                if (si.elbase != BADADDR)
                    result["element_base"] = format_ea(si.elbase);
                result["element_size"] = si.get_jtable_element_size();

                // Classify jump table pattern (from RE of arm.so)
                const char *jt_pattern = nullptr;
                switch (insn.itype) {
                    case ARM_ITYPE_BR:
                    case ARM_ITYPE_TBB:
                    case ARM_ITYPE_TBH:
                        jt_pattern = "tb"; break;
                    case ARM_ITYPE_BRAB:
                    case ARM_ITYPE_BRAB2:
                        jt_pattern = "ptn2"; break;
                    case ARM_ITYPE_BLR:
                        jt_pattern = "ptn1"; break;
                    case ARM_ITYPE_LDR_PC:
                        jt_pattern = "ldrpc"; break;
                }
                if (jt_pattern != nullptr)
                    result["jump_table_pattern"] = jt_pattern;

                json cases = json::array();
                if (si.get_jtable_element_size() > 0) {
                    size_t ncases = si.get_jtable_size();
                    for (size_t i = 0; i < ncases && i < 100; i++) {
                        ea_t slot = si.jumps + i * si.get_jtable_element_size();
                        ea_t case_ea = BADADDR;

                        if (si.get_jtable_element_size() == 4) {
                            uint32 offset = get_dword(slot);
                            if (offset != 0xFFFFFFFF)
                                case_ea = si.elbase + static_cast<int32>(offset);
                        } else if (si.get_jtable_element_size() == 8) {
                            uint64 val = get_qword(slot);
                            if (val != BADADDR)
                                case_ea = val;
                        } else if (si.get_jtable_element_size() == 2) {
                            uint16 offset = get_word(slot);
                            case_ea = si.elbase + static_cast<int16>(offset);
                        } else if (si.get_jtable_element_size() == 1) {
                            uint8 offset = get_byte(slot);
                            case_ea = si.elbase + offset * 2;
                        }

                        if (case_ea != BADADDR)
                            cases.push_back(json{{"case_index", i}, {"target", format_ea(case_ea)}});
                    }
                }
                result["cases"] = cases;
            } else {
                result["is_switch"] = false;

                const op_t &op = insn.ops[0];

                if (op.type == o_reg) {
                    result["branch_type"] = "register_indirect";
                    result["register"] = op.reg;

                    qstring reg_name;
                    get_reg_name(&reg_name, op.reg, get_dtype_size(op.dtype));
                    result["register_name"] = reg_name.c_str();

                    func_t *func = get_func(ea);
                    if (func != nullptr) {
                        reg_value_info_t reg_value;
                        if (find_reg_value_info(&reg_value, ea, op.reg, 0)) {
                            result["register_tracking"] = json{
                                {"state", reg_value.is_unknown() ? "unknown" : (reg_value.is_num() ? "resolved" : "spd")}
                            };

                            uval_t target_addr;
                            if (reg_value.get_num(&target_addr)) {
                                result["resolved_target"] = format_ea(target_addr);
                                result["resolution_method"] = "register_tracking";

                                func_t *target_func = get_func(target_addr);
                                if (target_func != nullptr) {
                                    qstring target_name;
                                    get_func_name(&target_name, target_func->start_ea);
                                    result["resolved_function"] = target_name.c_str();
                                }
                            }

                            json value_defs = json::array();
                            for (size_t i = 0; i < reg_value.vals_size() && i < 10; i++) {
                                const reg_value_def_t *def = reg_value.vals_begin() + i;
                                json def_json;
                                if (def->def_ea != BADADDR) {
                                    def_json["address"] = format_ea(def->def_ea);
                                    qstring dis, clean_dis;
                                    generate_disasm_line(&dis, def->def_ea, GENDSM_FORCE_CODE);
                                    tag_remove(&clean_dis, dis);
                                    def_json["disassembly"] = clean_dis.c_str();
                                }
                                value_defs.push_back(def_json);
                            }
                            if (!value_defs.empty())
                                result["value_definitions"] = value_defs;
                        }
                    }
                } else if (op.type == o_mem || op.type == o_displ || op.type == o_phrase) {
                    result["branch_type"] = "memory_indirect";
                    if (op.addr != BADADDR)
                        result["memory_address"] = format_ea(op.addr);
                } else {
                    result["branch_type"] = "unknown";
                }

                json targets = json::array();
                xrefblk_t xb;
                for (bool ok = xb.first_from(ea, XREF_FAR); ok && targets.size() < 100; ok = xb.next_from()) {
                    if (xb.iscode)
                        targets.push_back(format_ea(xb.to));
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

            int target_reg;
            if (params["register"].is_string()) {
                std::string reg_name = params["register"].get<std::string>();
                target_reg = str2reg(reg_name.c_str());
                if (target_reg < 0) {
                    throw std::runtime_error("Unknown register name: " + reg_name);
                }
            } else {
                target_reg = params["register"].get<int>();
            }

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
                    qstring dis, clean_dis;
                    generate_disasm_line(&dis, addr, GENDSM_FORCE_CODE);
                    tag_remove(&clean_dis, dis);

                    qstring mnem;
                    print_insn_mnem(&mnem, addr);

                    json entry;
                    entry["address"] = format_ea(addr);
                    entry["disassembly"] = clean_dis.c_str();
                    entry["mnemonic"] = mnem.c_str();
                    entry["modifies_register"] = modifies_reg;
                    entry["reads_register"] = reads_reg;

                    // Add operand details
                    json operands = json::array();
                    for (int i = 0; i < UA_MAXOP && insn.ops[i].type != o_void; i++) {
                        qstring op_str, clean_op;
                        print_operand(&op_str, addr, i);
                        tag_remove(&clean_op, op_str);
                        operands.push_back(clean_op.c_str());
                    }
                    entry["operands"] = operands;

                    trace.push_back(entry);

                    if (trace.size() >= 50) {
                        break;
                    }
                }
            }

            qstring resolved_name;
            get_reg_name(&resolved_name, target_reg, sizeof(ea_t));

            return json{
                {"address", format_ea(ea)},
                {"register", target_reg},
                {"register_name", resolved_name.empty() ? json(nullptr) : json(resolved_name.c_str())},
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
                                {"description", "Register name (e.g. \"rax\", \"rbx\") or number"}
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
