#include "tools/tools.hpp"
#include <offset.hpp>

namespace ida_mcp::tools::offsets {
    namespace {
        json handle_apply_offset(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();
            int operand = params["operand"].get<int>();
            auto target_opt = parse_ea(params["target"]);
            if (!target_opt.has_value()) {
                throw std::runtime_error("Invalid target address format");
            }
            ea_t target = target_opt.value();

            bool success = op_offset(ea, operand, REF_OFF32, target);

            return json{
                {"address", format_ea(ea)},
                {"operand", operand},
                {"target", format_ea(target)},
                {"success", success}
            };
        }

        json handle_get_offset_expression(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();
            int operand = params["operand"].get<int>();

            qstring expr;
            print_operand(&expr, ea, operand);

            return json{
                {"address", format_ea(ea)},
                {"operand", operand},
                {"expression", expr.c_str()}
            };
        }

        json handle_apply_offset_ex(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();
            int operand = params["operand"].get<int>();
            int reftype = params["reftype"].get<int>();
            auto target_opt = parse_ea(params["target"]);
            if (!target_opt.has_value()) {
                throw std::runtime_error("Invalid target address format");
            }
            ea_t target = target_opt.value();
            auto base_opt = parse_ea(params["base"]);
            if (!base_opt.has_value()) {
                throw std::runtime_error("Invalid base address format");
            }
            ea_t base = base_opt.value();
            adiff_t tdelta = params["tdelta"].get<uint64_t>();

            refinfo_t ri;
            ri.init(reftype, base, target, tdelta);

            bool success = op_offset_ex(ea, operand, &ri);

            return json{
                {"address", format_ea(ea)},
                {"operand", operand},
                {"reftype", reftype},
                {"target", format_ea(target)},
                {"base", format_ea(base)},
                {"tdelta", static_cast<uint64_t>(tdelta)},
                {"success", success}
            };
        }

        json handle_calc_offset_base(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();
            int operand = params["operand"].get<int>();

            ea_t base = calc_offset_base(ea, operand);

            return json{
                {"address", format_ea(ea)},
                {"operand", operand},
                {"base", base == BADADDR ? nullptr : json(format_ea(base))}
            };
        }

        json handle_calc_reference_target(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();
            int operand = params["operand"].get<int>();

            // Get operand value
            insn_t insn;
            decode_insn(&insn, ea);

            ea_t target = BADADDR;
            if (operand >= 0 && operand < UA_MAXOP) {
                const op_t &op = insn.ops[operand];
                if (op.type == o_mem || op.type == o_near || op.type == o_far) {
                    target = op.addr;
                }
            }

            return json{
                {"address", format_ea(ea)},
                {"operand", operand},
                {"target", target == BADADDR ? nullptr : json(format_ea(target))}
            };
        }

        json handle_calc_reference_base(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();
            int operand = params["operand"].get<int>();

            ea_t base = calc_offset_base(ea, operand);

            return json{
                {"address", format_ea(ea)},
                {"operand", operand},
                {"base", base == BADADDR ? nullptr : json(format_ea(base))}
            };
        }

        json handle_get_default_reftype(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();
            int operand = params["operand"].get<int>();

            reftype_t reftype = get_default_reftype(ea);

            return json{
                {"address", format_ea(ea)},
                {"operand", operand},
                {"default_reftype", static_cast<int>(reftype)}
            };
        }
    } // anonymous namespace

    void register_tools(mcp::McpServer &server) {
        // apply_offset
        {
            mcp::ToolDefinition def;
            def.name = "apply_offset";
            def.description = "Apply offset to operand";
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
                            "operand", {
                                {"type", "number"},
                                {"description", "Operand number"}
                            }
                        },
                        {
                            "target", {
                                {"type", "string"},
                                {"description", "Target hex address"}
                            }
                        }
                    }
                },
                {"required", json::array({"address", "operand", "target"})}
            };
            server.register_tool(def, handle_apply_offset);
        }

        // get_offset_expression
        {
            mcp::ToolDefinition def;
            def.name = "get_offset_expression";
            def.description = "Get offset expression";
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
                            "operand", {
                                {"type", "number"},
                                {"description", "Operand number"}
                            }
                        }
                    }
                },
                {"required", json::array({"address", "operand"})}
            };
            server.register_tool(def, handle_get_offset_expression);
        }

        // apply_offset_ex
        {
            mcp::ToolDefinition def;
            def.name = "apply_offset_ex";
            def.description = "Apply offset with reftype control";
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
                            "operand", {
                                {"type", "number"},
                                {"description", "Operand number"}
                            }
                        },
                        {
                            "reftype", {
                                {"type", "number"},
                                {"description", "Reference type"}
                            }
                        },
                        {
                            "target", {
                                {"type", "string"},
                                {"description", "Target hex address"}
                            }
                        },
                        {
                            "base", {
                                {"type", "string"},
                                {"description", "Base hex address"}
                            }
                        },
                        {
                            "tdelta", {
                                {"type", "number"},
                                {"description", "Target delta"}
                            }
                        }
                    }
                },
                {"required", json::array({"address", "operand", "reftype", "target", "base", "tdelta"})}
            };
            server.register_tool(def, handle_apply_offset_ex);
        }

        // calc_offset_base
        {
            mcp::ToolDefinition def;
            def.name = "calc_offset_base";
            def.description = "Calculate offset base address";
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
                            "operand", {
                                {"type", "number"},
                                {"description", "Operand number"}
                            }
                        }
                    }
                },
                {"required", json::array({"address", "operand"})}
            };
            server.register_tool(def, handle_calc_offset_base);
        }

        // calc_reference_target
        {
            mcp::ToolDefinition def;
            def.name = "calc_reference_target";
            def.description = "Calculate reference target address";
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
                            "operand", {
                                {"type", "number"},
                                {"description", "Operand number"}
                            }
                        }
                    }
                },
                {"required", json::array({"address", "operand"})}
            };
            server.register_tool(def, handle_calc_reference_target);
        }

        // calc_reference_base
        {
            mcp::ToolDefinition def;
            def.name = "calc_reference_base";
            def.description = "Calculate reference base address";
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
                            "operand", {
                                {"type", "number"},
                                {"description", "Operand number"}
                            }
                        }
                    }
                },
                {"required", json::array({"address", "operand"})}
            };
            server.register_tool(def, handle_calc_reference_base);
        }

        // get_default_reftype
        {
            mcp::ToolDefinition def;
            def.name = "get_default_reftype";
            def.description = "Get default reference type";
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
                            "operand", {
                                {"type", "number"},
                                {"description", "Operand number"}
                            }
                        }
                    }
                },
                {"required", json::array({"address", "operand"})}
            };
            server.register_tool(def, handle_get_default_reftype);
        }
    }
} // namespace ida_mcp::tools::offsets
