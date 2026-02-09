#include "tools/tools.hpp"
#include <funcs.hpp>
#include <frame.hpp>
#include <ua.hpp>
#include <allins.hpp>

namespace ida_mcp::tools::functions {
    namespace {
        // ARM64 PAC constants
#define aux_pac 0x10000
#define PAC_KEYMASK 0x07
#define PAC_KEY_IA 0x00
#define PAC_KEY_IB 0x01

        // Helper: Detect if function uses PAC (PACIASP/PACIBSP in prologue)
        bool detect_pac_protection(func_t *func) {
            // Check the first few instructions for PACIASP or PACIBSP
            ea_t ea = func->start_ea;
            ea_t end = (func->end_ea - func->start_ea > 32) ? func->start_ea + 32 : func->end_ea;

            for (ea_t addr = ea; addr < end; addr = next_head(addr, end)) {
                insn_t insn;
                if (decode_insn(&insn, addr) > 0) {
                    // Check if it's a PAC instruction
                    if ((insn.auxpref & aux_pac) != 0 && insn.itype == ARM_pac) {
                        int pac_key = insn.insnpref & PAC_KEYMASK;
                        // PACIASP/PACIBSP are common function prologues
                        if (pac_key == PAC_KEY_IA || pac_key == PAC_KEY_IB) {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        // Helper: Get PAC key used in function prologue
        const char *get_pac_key_for_function(func_t *func) {
            ea_t ea = func->start_ea;
            ea_t end = (func->end_ea - func->start_ea > 32) ? func->start_ea + 32 : func->end_ea;

            for (ea_t addr = ea; addr < end; addr = next_head(addr, end)) {
                insn_t insn;
                if (decode_insn(&insn, addr) > 0) {
                    if ((insn.auxpref & aux_pac) != 0 && insn.itype == ARM_pac) {
                        int pac_key = insn.insnpref & PAC_KEYMASK;
                        if (pac_key == PAC_KEY_IA) return "IA";
                        if (pac_key == PAC_KEY_IB) return "IB";
                    }
                }
            }
            return nullptr;
        }

        const size_t FUNCTIONS_PAGE_SIZE = 1000;

        // List functions with cursor-based pagination
        static json list_functions(const json &params) {
            // Parse cursor (it's just the index as a string)
            size_t start_index = 0;
            if (params.contains("cursor") && !params["cursor"].is_null()) {
                std::string cursor_str = params["cursor"];
                start_index = std::stoull(cursor_str);
            }

            size_t func_qty = get_func_qty();

            if (start_index >= func_qty) {
                // Cursor is past the end - return empty result
                return json{
                    {"functions", json::array()},
                    {"total", func_qty},
                    {"returned", 0}
                };
            }

            size_t end_index = std::min(start_index + FUNCTIONS_PAGE_SIZE, func_qty);

            // Collect functions
            json funcs = json::array();
            for (size_t i = start_index; i < end_index; i++) {
                func_t *func = getn_func(i);
                if (func == nullptr) {
                    continue;
                }

                // Get function name
                qstring name;
                std::string name_str;
                if (get_func_name(&name, func->start_ea) > 0) {
                    name_str = name.c_str();
                } else {
                    qstring formatted_name;
                    formatted_name.sprnt("sub_%llX", static_cast<uint64>(func->start_ea));
                    name_str = formatted_name.c_str();
                }

                funcs.push_back(json{
                    {"name", name_str},
                    {"address", format_ea(func->start_ea)},
                    {"size", func->end_ea - func->start_ea}
                });
            }

            json result = json{
                {"functions", funcs},
                {"total", func_qty},
                {"returned", funcs.size()}
            };

            // Add nextCursor if there are more results
            if (end_index < func_qty) {
                result["nextCursor"] = std::to_string(end_index);
            }

            return result;
        }

        // Get detailed function attributes
        static json get_function_attributes(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            func_t *func = get_func(ea);
            if (func == nullptr) {
                throw std::runtime_error("Address " + format_ea(ea) + " is not in a function");
            }

            // Get function name
            qstring name;
            std::string name_str;
            if (get_func_name(&name, func->start_ea) > 0) {
                name_str = name.c_str();
            } else {
                qstring formatted_name;
                formatted_name.sprnt("sub_%llX", static_cast<uint64>(func->start_ea));
                name_str = formatted_name.c_str();
            }

            // Get frame size if it exists
            constexpr int64 NO_FRAME = -1;
            int64 frame_size = NO_FRAME;
            if (func->frame != BADADDR) {
                frame_size = get_frame_size(func);
            }

            json result = json{
                {"address", format_ea(func->start_ea)},
                {"name", name_str},
                {"start_ea", format_ea(func->start_ea)},
                {"end_ea", format_ea(func->end_ea)},
                {"size", func->end_ea - func->start_ea},
                {"flags", func->flags},
                {"frame_size", frame_size},
                {"is_library", (func->flags & FUNC_LIB) != 0},
                {"is_noret", (func->flags & FUNC_NORET) != 0},
                {"is_far", (func->flags & FUNC_FAR) != 0},
                {"is_thunk", (func->flags & FUNC_THUNK) != 0},
                {"is_tail", (func->flags & FUNC_TAIL) != 0}
            };

            // Check for PAC protection (ARM64E)
            if (detect_pac_protection(func)) {
                const char *pac_key = get_pac_key_for_function(func);
                result["pac_protected"] = true;
                if (pac_key) {
                    result["pac_key"] = pac_key;
                }
            }

            // Function tail information
            if ((func->flags & FUNC_TAIL) == 0) {
                // This is a function entry (not a tail), check if it has tails
                func_tail_iterator_t fti(func);
                json tails = json::array();
                int tail_count = 0;

                for (bool ok = fti.first(); ok; ok = fti.next()) {
                    const range_t &tail_range = fti.chunk();
                    tails.push_back(json{
                        {"start", format_ea(tail_range.start_ea)},
                        {"end", format_ea(tail_range.end_ea)},
                        {"size", tail_range.end_ea - tail_range.start_ea}
                    });
                    tail_count++;
                    if (tail_count >= 20) break; // Limit to 20 tails
                }

                if (!tails.empty()) {
                    result["has_tails"] = true;
                    result["tail_count"] = tail_count;
                    result["tails"] = tails;
                }
            } else {
                // This is a tail chunk, find the owner function
                func_t *owner = get_func(func->owner);
                if (owner != nullptr) {
                    qstring owner_name;
                    get_func_name(&owner_name, owner->start_ea);
                    result["tail_owner"] = json{
                        {"address", format_ea(owner->start_ea)},
                        {"name", owner_name.c_str()}
                    };
                }
            }

            return result;
        }

        // Get function signature/prototype
        static json get_function_signature(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            func_t *func = get_func(ea);
            if (func == nullptr) {
                throw std::runtime_error("Address " + format_ea(ea) + " is not in a function");
            }

            // Get function type information
            tinfo_t tif;
            qstring signature;

            json result;

            if (get_tinfo(&tif, func->start_ea)) {
                // Got type info - format it as declaration
                if (tif.print(&signature, nullptr, PRTYPE_1LINE | PRTYPE_SEMI)) {
                    result = json{
                        {"address", format_ea(ea)},
                        {"signature", signature.c_str()},
                        {"has_type_info", true}
                    };
                }
            }

            // Fallback: generate basic signature
            if (result.is_null()) {
                qstring name;
                if (get_func_name(&name, func->start_ea) > 0) {
                    signature = name;
                } else {
                    signature.sprnt("sub_%llX", static_cast<uint64>(func->start_ea));
                }

                result = json{
                    {"address", format_ea(ea)},
                    {"signature", std::string(signature.c_str()) + "(...)"},
                    {"has_type_info", false}
                };
            }

            // Add PAC information if present
            if (detect_pac_protection(func)) {
                const char *pac_key = get_pac_key_for_function(func);
                result["pac_protected"] = true;
                if (pac_key) {
                    result["pac_key"] = pac_key;
                }
            }

            return result;
        }
    } // anonymous namespace

    void register_tools(mcp::McpServer &server) {
        // list_functions tool
        {
            mcp::ToolDefinition def;
            def.name = "list_functions";
            def.description = "List functions with pagination";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "cursor", {
                                {"type", "string"},
                                {"description", "Pagination cursor"}
                            }
                        }
                    }
                }
            };
            server.register_tool(def, list_functions);
        }

        // get_function_attributes tool
        {
            mcp::ToolDefinition def;
            def.name = "get_function_attributes";
            def.description = "Get function attributes and flags";
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
            server.register_tool(def, get_function_attributes);
        }

        // get_function_signature tool
        {
            mcp::ToolDefinition def;
            def.name = "get_function_signature";
            def.description = "Get function signature/prototype";
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
            server.register_tool(def, get_function_signature);
        }
    }
} // namespace ida_mcp::tools::functions
