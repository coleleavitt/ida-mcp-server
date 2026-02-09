#include "tools/tools.hpp"
#include <ua.hpp>
#include <allins.hpp>

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
            return (itype >= ARM_ldar && itype <= ARM_stlxp) ||  // Load-Acquire/Store-Release
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
            return (itype >= ARM_aesd && itype <= ARM_aesmc) ||     // AES
                   (itype >= ARM_sha1c && itype <= ARM_sha256su1) || // SHA-1/256
                   (itype >= ARM_sha512h && itype <= ARM_sha512su1) || // SHA-512
                   (itype >= ARM_sm3partw1 && itype <= ARM_sm3tt2b) || // SM3
                   (itype >= ARM_sm4e && itype <= ARM_sm4ekey) ||      // SM4
                   (itype == ARM_crc32 || itype == ARM_crc32c);        // CRC32
        }

        // Helper: Check if instruction is PAC/AUT
        bool is_pac_instruction(const insn_t &insn) {
            return (insn.auxpref & aux_pac) != 0;
        }

        // Helper: Get PAC key name
        const char* get_pac_key_name(int key) {
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
        const char* get_pac_address_mode(int adr) {
            switch (adr) {
                case PAC_ADR_GPR: return "gpr";
                case PAC_ADR_X17: return "x17";
                case PAC_ADR_X30: return "x30_lr";
                default: return "unknown";
            }
        }

        // Helper: Get PAC modifier mode
        const char* get_pac_modifier_mode(int mod) {
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

            insn_t insn;
            int len = decode_insn(&insn, ea);

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

            // Add ARM64-specific instruction classification
            json arm64_info = json::object();
            bool has_arm64_info = false;

            // Check for PAC instructions
            if (is_pac_instruction(insn)) {
                int pac_flags = insn.insnpref;  // pac_flags is mapped to insnpref
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

            if (has_arm64_info) {
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
            insn_t insn;
            int len = decode_insn(&insn, ea);

            if (len <= 0) {
                throw std::runtime_error("Failed to decode instruction at " + format_ea(ea));
            }

            // Generate disassembly line
            qstring disasm;
            generate_disasm_line(&disasm, ea, GENDSM_FORCE_CODE);

            return json{
                {"address", format_ea(ea)},
                {"mnemonic", mnem.c_str()},
                {"disassembly", disasm.c_str()},
                {"size", insn.size}
            };
        }

        json handle_get_operand_info(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            insn_t insn;
            int len = decode_insn(&insn, ea);

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
    }
} // namespace ida_mcp::tools::instructions
