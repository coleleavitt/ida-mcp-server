#include "tools/tools.hpp"

#ifdef HAS_HEXRAYS
#include <hexrays.hpp>
#include <lines.hpp>
#endif

namespace ida_mcp::tools::microcode {
    namespace {
#ifdef HAS_HEXRAYS
        std::string mopt_to_string(mopt_t t) {
            switch (t) {
                case mop_z: return "zero";
                case mop_r: return "reg";
                case mop_n: return "number";
                case mop_d: return "insn";
                case mop_S: return "stkvar";
                case mop_v: return "global";
                case mop_b: return "block";
                case mop_f: return "callinfo";
                case mop_l: return "local";
                case mop_a: return "addr";
                case mop_h: return "helper";
                case mop_str: return "string";
                case mop_c: return "case";
                case mop_fn: return "fpc";
                case mop_p: return "pair";
                case mop_sc: return "scattered";
                default: return "unknown";
            }
        }

        json operand_to_json(const mop_t &op) {
            json j;
            j["type"] = mopt_to_string(op.t);
            j["size"] = op.size;

            switch (op.t) {
                case mop_r:
                    j["reg"] = static_cast<int>(op.r);
                    break;
                case mop_n:
                    if (op.nnn != nullptr)
                        j["value"] = static_cast<int64_t>(op.nnn->value);
                    break;
                case mop_v:
                    j["addr"] = format_ea(op.g);
                    break;
                case mop_S:
                    if (op.s != nullptr)
                        j["offset"] = static_cast<int64_t>(op.s->off);
                    break;
                case mop_d:
                    if (op.d != nullptr)
                        j["inner_opcode"] = static_cast<int>(op.d->opcode);
                    break;
                case mop_b:
                    j["block"] = op.b;
                    break;
                case mop_h:
                    if (op.helper != nullptr)
                        j["name"] = op.helper;
                    break;
                case mop_str:
                    if (op.cstr != nullptr)
                        j["string"] = op.cstr;
                    break;
                default:
                    break;
            }
            return j;
        }

        json insn_to_json(const minsn_t &insn) {
            json j;
            j["ea"] = format_ea(insn.ea);
            j["opcode"] = static_cast<int>(insn.opcode);

            qstring mnem;
            insn.print(&mnem);
            qstring clean;
            tag_remove(&clean, mnem);
            j["text"] = clean.c_str();

            if (insn.l.t != mop_z)
                j["left"] = operand_to_json(insn.l);
            if (insn.r.t != mop_z)
                j["right"] = operand_to_json(insn.r);
            if (insn.d.t != mop_z)
                j["dest"] = operand_to_json(insn.d);

            return j;
        }

        static json get_microcode(const json &params) {
            if (!init_hexrays_plugin())
                throw std::runtime_error("Hexrays decompiler not available");

            if (!params.contains("address") || !params["address"].is_string())
                throw std::runtime_error("Missing required parameter: address");

            auto addr = parse_ea(params["address"].get<std::string>());
            if (!addr.has_value())
                throw std::runtime_error("Invalid address");

            func_t *func = get_func(addr.value());
            if (func == nullptr)
                throw std::runtime_error("Address is not in a function");

            int maturity_int = MMAT_GLBOPT3;
            if (params.contains("maturity") && params["maturity"].is_number_integer())
                maturity_int = params["maturity"].get<int>();

            if (maturity_int < MMAT_GENERATED || maturity_int > MMAT_LVARS)
                throw std::runtime_error("Invalid maturity level (1-8)");

            auto reqmat = static_cast<mba_maturity_t>(maturity_int);

            int max_insns = 500;
            if (params.contains("max_instructions") && params["max_instructions"].is_number_integer())
                max_insns = params["max_instructions"].get<int>();

            hexrays_failure_t hf;
            mba_ranges_t mbr(func);
            mba_t *mba = gen_microcode(mbr, &hf, nullptr, DECOMP_NO_WAIT, reqmat);

            if (mba == nullptr) {
                qstring err = hf.desc();
                throw std::runtime_error(std::string("Microcode generation failed: ") + err.c_str());
            }

            json blocks = json::array();
            int total_insns = 0;
            bool truncated = false;

            for (int i = 0; i < mba->qty && !truncated; i++) {
                mblock_t *blk = mba->get_mblock(i);
                if (blk == nullptr)
                    continue;

                json blk_json;
                blk_json["index"] = i;
                blk_json["start"] = format_ea(blk->start);
                blk_json["end"] = format_ea(blk->end);
                blk_json["type"] = blk->type;

                json succs = json::array();
                for (int s = 0; s < blk->nsucc(); s++)
                    succs.push_back(blk->succ(s));
                blk_json["successors"] = succs;

                json preds = json::array();
                for (int p = 0; p < blk->npred(); p++)
                    preds.push_back(blk->pred(p));
                blk_json["predecessors"] = preds;

                json insns = json::array();
                for (minsn_t *ins = blk->head; ins != nullptr; ins = ins->next) {
                    if (total_insns >= max_insns) {
                        truncated = true;
                        break;
                    }
                    insns.push_back(insn_to_json(*ins));
                    total_insns++;
                }
                blk_json["instructions"] = insns;
                blocks.push_back(blk_json);
            }

            json result;
            result["function"] = get_function_name(func);
            result["address"] = format_ea(func->start_ea);
            result["maturity"] = static_cast<int>(mba->maturity);
            result["block_count"] = mba->qty;
            result["total_instructions"] = total_insns;
            result["truncated"] = truncated;
            result["blocks"] = blocks;

            delete mba;
            return result;
        }
#endif
    }

    void register_tools(mcp::McpServer &server) {
#ifdef HAS_HEXRAYS
        mcp::ToolDefinition def;
        def.name = "get_microcode";
        def.description =
                "Generate and dump the Hex-Rays microcode for a function at a specified maturity level. "
                "Returns basic blocks with microinstructions, operands, and control flow edges. "
                "Maturity levels: 1=GENERATED, 2=PREOPTIMIZED, 3=LOCOPT, 4=CALLS, 5=GLBOPT1, 6=GLBOPT2, 7=GLBOPT3, 8=LVARS";
        def.input_schema = json{
            {"type", "object"},
            {
                "properties", {
                    {
                        "address", {
                            {"type", "string"},
                            {"description", "Hex address of function to generate microcode for"}
                        }
                    },
                    {
                        "maturity", {
                            {"type", "integer"},
                            {
                                "description",
                                "Microcode maturity level 1-8 (default: 7 = GLBOPT3). Lower = closer to raw assembly, higher = more optimized."
                            }
                        }
                    },
                    {
                        "max_instructions", {
                            {"type", "integer"},
                            {
                                "description",
                                "Max number of microinstructions to return (default: 500). Prevents huge outputs."
                            }
                        }
                    }
                }
            },
            {"required", json::array({"address"})}
        };
        server.register_tool(def, get_microcode);
#endif
    }
}
