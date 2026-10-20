#include "tools/tools.hpp"
#include <ua.hpp>
#include <allins.hpp>
#include <lines.hpp>
#include <regfinder.hpp>
#include <memory>

namespace ida_mcp::tools::instructions {
    namespace {
        // ARM64 specific constants (from arm.hpp)
#define aux_pac        0x10000
#define PAC_KEYMASK    0x07
#define PAC_KEY_IA     0x00
#define PAC_KEY_IB     0x01
#define PAC_KEY_DA     0x02
#define PAC_KEY_DB     0x03
#define PAC_KEY_GA     0x04
#define PAC_ADRMASK   (3<<3)
#define PAC_ADR_GPR   (0<<3)
#define PAC_ADR_X17   (1<<3)
#define PAC_ADR_X30   (2<<3)
#define PAC_MODMASK   (3<<5)
#define PAC_MOD_GPR   (0<<5)
#define PAC_MOD_ZR    (1<<5)
#define PAC_MOD_X16   (2<<5)
#define PAC_MOD_SP    (3<<5)

        // Helper: Check if instruction is ARM64 atomic operation
        bool is_atomic_operation(uint16 itype) {
            return (itype >= ARM_ldar && itype <= ARM_stlxp) || // Load-Acquire/Store-Release
                   (itype >= ARM_ldadd && itype <= ARM_ldaddal) ||
                   (itype >= ARM_ldclr && itype <= ARM_ldclral) ||
                   (itype >= ARM_ldeor && itype <= ARM_ldeoral) ||
                   (itype >= ARM_ldset && itype <= ARM_ldsetal) ||
                   (itype >= ARM_ldsmax && itype <= ARM_ldsmaxal) ||
                   (itype >= ARM_ldsmin && itype <= ARM_ldsminal) ||
                   (itype >= ARM_ldumax && itype <= ARM_ldumaxal) ||
                   (itype >= ARM_ldumin && itype <= ARM_lduminal) ||
                   (itype >= ARM_cas && itype <= ARM_caspal) ||
                   (itype == ARM_ldapr) || (itype == ARM_stllr) ||
                   (itype == ARM_ldapur) || (itype == ARM_stlur);
        }

        // Helper: Check if instruction is memory barrier
        bool is_memory_barrier(uint16 itype) {
            return itype == ARM_dmb || itype == ARM_dsb || itype == ARM_isb ||
                   itype == ARM_sb || itype == ARM_ssbb || itype == ARM_pssbb;
        }

        // Helper: Check if instruction is crypto
        bool is_crypto_instruction(uint16 itype) {
            return (itype >= ARM_aesd && itype <= ARM_aesmc) || // AES
                   (itype >= ARM_sha1c && itype <= ARM_sha256su1) || // SHA-1/256
                   (itype >= ARM_sha512h && itype <= ARM_sha512su1) || // SHA-512
                   (itype >= ARM_sm3partw1 && itype <= ARM_sm3tt2b) || // SM3
                   (itype >= ARM_sm4e && itype <= ARM_sm4ekey) || // SM4
                   (itype == ARM_crc32 || itype == ARM_crc32c); // CRC32
        }

        // Helper: Check if instruction is PAC/AUT
        bool is_pac_instruction(const insn_t &insn) {
            return (insn.auxpref & aux_pac) != 0;
        }

        // Helper: Get PAC key name
        const char *get_pac_key_name(int key) {
            switch (key) {
                case PAC_KEY_IA: return "IA";
                case PAC_KEY_IB: return "IB";
                case PAC_KEY_DA: return "DA";
                case PAC_KEY_DB: return "DB";
                case PAC_KEY_GA: return "GA";
                default: return "unknown";
            }
        }

        // Helper: Get PAC address mode
        const char *get_pac_address_mode(int adr) {
            switch (adr) {
                case PAC_ADR_GPR: return "gpr";
                case PAC_ADR_X17: return "x17";
                case PAC_ADR_X30: return "x30_lr";
                default: return "unknown";
            }
        }

        // Helper: Get PAC modifier mode
        const char *get_pac_modifier_mode(int mod) {
            switch (mod) {
                case PAC_MOD_GPR: return "gpr_sp";
                case PAC_MOD_ZR: return "zero";
                case PAC_MOD_X16: return "x16";
                case PAC_MOD_SP: return "sp";
                default: return "unknown";
            }
        }

        const char *optype_to_string(optype_t type) {
            switch (type) {
                case o_void: return "void";
                case o_reg: return "register";
                case o_mem: return "memory";
                case o_phrase: return "phrase";
                case o_displ: return "displacement";
                case o_imm: return "immediate";
                case o_far: return "far_address";
                case o_near: return "near_address";
                case o_idpspec0:
                case o_idpspec1:
                case o_idpspec2:
                case o_idpspec3:
                case o_idpspec4:
                case o_idpspec5:
                    return "processor_specific";
                default: return "unknown";
            }
        }

        json handle_decode_insn(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            // Use heap allocation to avoid stack corruption if insn_t size differs between SDK versions
            auto insn_ptr = std::make_unique<insn_t>();
            // insn_t default constructor handles initialization
            int len = decode_insn(insn_ptr.get(), ea);
            insn_t& insn = *insn_ptr;

            if (len <= 0) {
                throw std::runtime_error("No instruction at " + format_ea(ea));
            }

            // Get mnemonic
            qstring mnem;
            print_insn_mnem(&mnem, ea);

            // Collect operands
            json operands = json::array();
            for (int i = 0; i < UA_MAXOP; i++) {
                const op_t &op = insn.ops[i];
                if (op.type == o_void) {
                    break;
                }

                operands.push_back(json{
                    {"index", i},
                    {"type", optype_to_string(op.type)},
                    {"dtype", static_cast<int>(op.dtype)},
                    {"reg", static_cast<int>(op.reg)},
                    {"value", static_cast<uint64_t>(op.value)},
                    {"addr", format_ea(op.addr)}
                });
            }

            json result = json{
                {"address", format_ea(ea)},
                {"mnemonic", mnem.c_str()},
                {"size", insn.size},
                {"itype", insn.itype},
                {"operand_count", operands.size()},
                {"operands", operands}
            };

            // Add ARM64-specific instruction classification (only for ARM processors)
            qstring procname = inf_get_procname();
            bool is_arm = procname.find("ARM") != qstring::npos ||
                          procname.find("arm") != qstring::npos ||
                          procname.find("AARCH64") != qstring::npos ||
                          procname.find("aarch64") != qstring::npos;

            json arm64_info = json::object();
            bool has_arm64_info = false;

            if (is_arm) {
            // Check for PAC instructions
            if (is_pac_instruction(insn)) {
                int pac_flags = insn.insnpref; // pac_flags is mapped to insnpref
                int key = pac_flags & PAC_KEYMASK;
                int adr = pac_flags & PAC_ADRMASK;
                int mod = pac_flags & PAC_MODMASK;

                arm64_info["pac"] = json{
                    {"is_pac", true},
                    {"key", get_pac_key_name(key)},
                    {"address_mode", get_pac_address_mode(adr)},
                    {"modifier_mode", get_pac_modifier_mode(mod)}
                };
                has_arm64_info = true;
            }

            // Check for atomic operations
            if (is_atomic_operation(insn.itype)) {
                arm64_info["atomic"] = true;
                has_arm64_info = true;
            }

            // Check for memory barriers
            if (is_memory_barrier(insn.itype)) {
                arm64_info["memory_barrier"] = true;
                has_arm64_info = true;
            }

            // Check for crypto instructions
            if (is_crypto_instruction(insn.itype)) {
                arm64_info["crypto"] = true;
                has_arm64_info = true;
            }

            // Check for system register access (MRS/MSR)
            if (insn.itype == ARM_mrs || insn.itype == ARM_msr) {
                arm64_info["system_register"] = true;
                has_arm64_info = true;
            }

            // Check for exception instructions
            if (insn.itype == ARM_svc || insn.itype == ARM_hvc || insn.itype == ARM_smc) {
                arm64_info["exception"] = true;
                has_arm64_info = true;
            }

            } // end if (is_arm)

            if (is_arm && has_arm64_info) {
                result["arm64"] = arm64_info;
            }

            return result;
        }

        json handle_print_insn(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            qstring mnem;
            if (!print_insn_mnem(&mnem, ea)) {
                throw std::runtime_error("No instruction at " + format_ea(ea));
            }

            // Decode to get full disassembly
            auto insn_ptr = std::make_unique<insn_t>();
            int len = decode_insn(insn_ptr.get(), ea);
            insn_t& insn = *insn_ptr;

            if (len <= 0) {
                throw std::runtime_error("Failed to decode instruction at " + format_ea(ea));
            }

            // Generate disassembly line
            qstring disasm, clean_disasm;
            generate_disasm_line(&disasm, ea, GENDSM_FORCE_CODE);
            tag_remove(&clean_disasm, disasm);

            return json{
                {"address", format_ea(ea)},
                {"mnemonic", mnem.c_str()},
                {"disassembly", clean_disasm.c_str()},
                {"size", insn.size}
            };
        }

        json handle_get_operand_info(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            auto insn_ptr = std::make_unique<insn_t>();
            int len = decode_insn(insn_ptr.get(), ea);
            insn_t& insn = *insn_ptr;

            if (len <= 0) {
                throw std::runtime_error("No instruction at " + format_ea(ea));
            }

            // If operand_index specified, return specific operand
            if (params.contains("operand_index")) {
                int idx = params["operand_index"].get<int>();
                if (idx < 0 || idx >= UA_MAXOP) {
                    throw std::runtime_error("Invalid operand index");
                }

                const op_t &op = insn.ops[idx];
                if (op.type == o_void) {
                    throw std::runtime_error("No operand at index " + std::to_string(idx));
                }

                return json{
                    {"index", idx},
                    {"type", optype_to_string(op.type)},
                    {"dtype", static_cast<int>(op.dtype)},
                    {"reg", static_cast<int>(op.reg)},
                    {"value", static_cast<uint64_t>(op.value)},
                    {"addr", format_ea(op.addr)},
                    {"flags", static_cast<uint32_t>(op.flags)}
                };
            }

            // Return all operands
            json operands = json::array();
            for (int i = 0; i < UA_MAXOP; i++) {
                const op_t &op = insn.ops[i];
                if (op.type == o_void) {
                    break;
                }

                operands.push_back(json{
                    {"index", i},
                    {"type", optype_to_string(op.type)},
                    {"dtype", static_cast<int>(op.dtype)},
                    {"reg", static_cast<int>(op.reg)},
                    {"value", static_cast<uint64_t>(op.value)},
                    {"addr", format_ea(op.addr)},
                    {"flags", static_cast<uint32_t>(op.flags)}
                });
            }

            return json{
                {"address", format_ea(ea)},
                {"operand_count", operands.size()},
                {"operands", operands}
            };
        }
    } // anonymous namespace

    namespace {
        const char *value_state(const reg_value_info_t &rvi) {
            if (rvi.empty()) return "undef";
            if (rvi.is_dead_end()) return "dead_end";
            if (rvi.aborted()) return "aborted";
            if (rvi.is_badinsn()) return "badinsn";
            if (rvi.is_unkinsn()) return "unkinsn";
            if (rvi.is_unkfunc()) return "unkfunc";
            if (rvi.is_unkloop()) return "unkloop";
            if (rvi.is_unkmult()) return "unkmult";
            if (rvi.is_unkxref()) return "unkxref";
            if (rvi.is_unkvals()) return "unkvals";
            if (rvi.is_num()) return "num";
            if (rvi.is_spd()) return "spd";
            if (rvi.is_numloop()) return "numloop";
            return "unrecognized";
        }

        json value_defs(const reg_value_info_t &rvi) {
            json out = json::array();
            for (const reg_value_def_t *d = rvi.vals_begin(); d != rvi.vals_end(); ++d) {
                json def = {{"def_ea", d->def_ea == BADADDR ? json(nullptr) : json(format_ea(d->def_ea))}};
                if (rvi.is_num() || rvi.is_numloop())
                    def["value"] = format_ea(d->val);
                else if (rvi.is_spd())
                    def["sp_delta"] = static_cast<int64>(d->val);
                json flags = json::array();
                if (d->is_short_insn()) flags.push_back("short_insn");
                if (d->is_pc_based()) flags.push_back("pc_based");
                if (d->is_like_got()) flags.push_back("like_got");
                if (d->had_delta()) flags.push_back("had_delta");
                def["flags"] = flags;
                out.push_back(def);
            }
            return out;
        }

        json operand_value(const insn_t &insn, int n, int max_depth) {
            const op_t &op = insn.ops[n];
            qstring text;
            print_operand(&text, insn.ea, n);
            tag_remove(&text);
            json result = {{"operand", n}, {"text", text.c_str()}, {"op_type", op.type}};

            reg_value_info_t rvi;
            if (!find_op_value_info(&rvi, insn, op, max_depth)) {
                result["tracked"] = false;
                return result;
            }
            result["tracked"] = true;
            result["state"] = value_state(rvi);
            if (rvi.is_numloop())
                result["stride"] = rvi.get_stride();
            if (rvi.aborted())
                result["aborting_depth"] = rvi.get_aborting_depth();
            result["values"] = value_defs(rvi);
            result["description"] = rvi.dstr().c_str();
            return result;
        }
    }

    // Value of an instruction operand from the register tracker, including the
    // 9.5 NUMLOOP state (a loop induction value with a constant stride).
    static json get_operand_value_info(const json &params) {
        if (!params.contains("address") || !params["address"].is_string())
            throw std::runtime_error("Missing required parameter: address");
        auto ea = parse_ea(params["address"].get<std::string>());
        if (!ea)
            throw std::runtime_error("Invalid address");
        insn_t insn;
        if (decode_insn(&insn, *ea) <= 0)
            throw std::runtime_error("No instruction at " + format_ea(*ea));
        const int max_depth = params.value("max_depth", 0);
        if (max_depth < 0)
            throw std::runtime_error("max_depth must be >= 0");

        json operands = json::array();
        if (params.contains("operand")) {
            if (!params["operand"].is_number_integer())
                throw std::runtime_error("operand must be an integer");
            const int n = params["operand"].get<int>();
            if (n < 0 || n >= UA_MAXOP || insn.ops[n].type == o_void)
                throw std::runtime_error("Instruction at " + format_ea(*ea) + " has no operand " + std::to_string(n));
            operands.push_back(operand_value(insn, n, max_depth));
        } else {
            for (int n = 0; n < UA_MAXOP && insn.ops[n].type != o_void; ++n)
                operands.push_back(operand_value(insn, n, max_depth));
        }
        return json{{"address", format_ea(insn.ea)}, {"operands", operands}};
    }

    void register_tools(mcp::McpServer &server) {
        // decode_insn
        {
            mcp::ToolDefinition def;
            def.name = "decode_insn";
            def.description = "Decode instruction details";
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
            server.register_tool(def, handle_decode_insn);
        }

        // print_insn
        {
            mcp::ToolDefinition def;
            def.name = "print_insn";
            def.description = "Get disassembly line";
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
            server.register_tool(def, handle_print_insn);
        }

        // get_operand_info
        {
            mcp::ToolDefinition def;
            def.name = "get_operand_info";
            def.description = "Get instruction operand info";
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
                            "operand_index", {
                                {"type", "number"},
                                {"description", "Operand index"}
                            }
                        }
                    }
                },
                {"required", json::array({"address"})}
            };
            server.register_tool(def, handle_get_operand_info);
        }

        {
            mcp::ToolDefinition def;
            def.name = "get_operand_value_info";
            def.description = "Find the value of a register or stack-variable operand with the register "
                    "tracker: state (num, spd, numloop with stride, or why it is unknown) and defining instructions";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Hex address of the instruction"}}},
                    {"operand", {{"type", "integer"}, {"minimum", 0}, {"description", "Operand index; omitted = every operand"}}},
                    {"max_depth", {{"type", "integer"}, {"minimum", 0}, {"default", 0}, {"description", "Tracking depth; 0 = the processor default"}}}
                }},
                {"required", json::array({"address"})}
            };
            server.register_tool(def, get_operand_value_info);
        }
    }
} // namespace ida_mcp::tools::instructions
