#include "tools/tools.hpp"
#include <funcs.hpp>
#include <typeinf.hpp>
#include <xref.hpp>
#include <frame.hpp>
#include <lines.hpp>
#include <tryblks.hpp>
#include <set>

namespace ida_mcp::tools::function_context {
    namespace {
        json handle_get_function_context(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            // Get optional parameters with defaults
            bool include_xrefs = params.contains("include_xrefs") && !params["include_xrefs"].is_null()
                                     ? params["include_xrefs"].get<bool>()
                                     : true;

            size_t max_depth = params.contains("max_depth") && !params["max_depth"].is_null()
                                   ? std::min(params["max_depth"].get<size_t>(), size_t(5))
                                   : 2;

            bool include_decompilation = params.contains("include_decompilation") && !params["include_decompilation"].
                                         is_null()
                                             ? params["include_decompilation"].get<bool>()
                                             : false;

            // Check if function exists
            func_t *func = get_func(ea);
            if (func == nullptr) {
                return json{
                    {"address", format_ea(ea)},
                    {"error", true},
                    {"warning", "No function found at address " + format_ea(ea)},
                    {"note", "This address may be in data, undefined code, or not analyzed as a function by IDA Pro."},
                    {
                        "suggestion",
                        "Try using get_address_info or get_func_limits to find the containing function, or ensure IDA has analyzed this address."
                    }
                };
            }

            // Get basic function info
            ea_t start_ea = func->start_ea;
            ea_t end_ea = func->end_ea;
            std::string name = get_function_name(func);

            // Get function signature
            qstring sig;
            tinfo_t tif;
            if (get_tinfo(&tif, start_ea)) {
                tif.print(&sig);
            }

            // Get function attributes
            uint32_t flags = func->flags;
            asize_t frame_size = get_frame_size(func);

            json context;
            context["address"] = format_ea(start_ea);
            context["name"] = name;
            context["signature"] = sig.c_str();
            context["bounds"] = {
                {"start", format_ea(start_ea)},
                {"end", format_ea(end_ea)},
                {"size", static_cast<uint64_t>(end_ea - start_ea)}
            };
            context["attributes"] = {
                {"flags", static_cast<uint64_t>(flags)},
                {"frame_size", static_cast<uint64_t>(frame_size)}
            };

            // Get cross-references if requested
            if (include_xrefs) {
                json callers = json::array();
                std::set<ea_t> seen_callers;

                // Get callers using xrefblk_t
                xrefblk_t xb;
                for (bool ok = xb.first_to(start_ea, XREF_FAR); ok; ok = xb.next_to()) {
                    if (xb.iscode) {
                        func_t *caller_func = get_func(xb.from);
                        if (caller_func != nullptr) {
                            ea_t caller_start = caller_func->start_ea;

                            if (seen_callers.find(caller_start) == seen_callers.end()) {
                                seen_callers.insert(caller_start);

                                std::string caller_name = get_function_name(caller_func);

                                const char *xref_type = "Code_Unknown";
                                switch (xb.type) {
                                    case fl_CF: xref_type = "Call_Far";
                                        break;
                                    case fl_CN: xref_type = "Call_Near";
                                        break;
                                    case fl_JF: xref_type = "Jump_Far";
                                        break;
                                    case fl_JN: xref_type = "Jump_Near";
                                        break;
                                }

                                json caller_obj;
                                caller_obj["address"] = format_ea(caller_start);
                                caller_obj["name"] = caller_name;
                                caller_obj["call_site"] = format_ea(xb.from);
                                caller_obj["type"] = xref_type;

                                callers.push_back(caller_obj);

                                if (callers.size() >= 50) {
                                    break; // Limit to 50 callers
                                }
                            }
                        }
                    }
                }

                // Get callees
                json callees = json::array();
                std::set<ea_t> seen_callees;

                for (ea_t addr = start_ea; addr < end_ea;) {
                    xrefblk_t xb_from;
                    for (bool ok = xb_from.first_from(addr, XREF_FAR); ok; ok = xb_from.next_from()) {
                        if (xb_from.iscode) {
                            func_t *callee_func = get_func(xb_from.to);
                            if (callee_func != nullptr) {
                                ea_t callee_start = callee_func->start_ea;

                                if (seen_callees.find(callee_start) == seen_callees.end()) {
                                    seen_callees.insert(callee_start);

                                    std::string callee_name = get_function_name(callee_func);

                                    const char *xref_type = "Code_Unknown";
                                    switch (xb_from.type) {
                                        case fl_CF: xref_type = "Call_Far";
                                            break;
                                        case fl_CN: xref_type = "Call_Near";
                                            break;
                                        case fl_JF: xref_type = "Jump_Far";
                                            break;
                                        case fl_JN: xref_type = "Jump_Near";
                                            break;
                                    }

                                    json callee_obj;
                                    callee_obj["address"] = format_ea(callee_start);
                                    callee_obj["name"] = callee_name;
                                    callee_obj["call_site"] = format_ea(addr);
                                    callee_obj["type"] = xref_type;

                                    callees.push_back(callee_obj);

                                    if (callees.size() >= 50) {
                                        break; // Limit to 50 callees
                                    }
                                }
                            }
                        }
                    }

                    if (callees.size() >= 50) {
                        break;
                    }

                    addr = next_head(addr, end_ea);
                    if (addr == BADADDR) {
                        break;
                    }
                }

                context["xrefs"] = {
                    {
                        "callers", {
                            {"count", callers.size()},
                            {"items", callers},
                            {"truncated", seen_callers.size() > 50}
                        }
                    },
                    {
                        "callees", {
                            {"count", callees.size()},
                            {"items", callees},
                            {"truncated", seen_callees.size() > 50}
                        }
                    },
                    {"analysis_depth", max_depth}
                };
            }

            // Get decompilation if requested
            if (include_decompilation) {
#ifdef WITH_HEXRAYS
                // Check if processor is CLI/.NET - Hexrays cannot decompile managed code
                qstring proc_name;
                get_processor_name(&proc_name);

                if (proc_name == "cli") {
                    context["decompilation"] = {
                        {"available", false},
                        {"note", "Decompilation not supported for .NET/CLI binaries (IL bytecode, not native assembly)"},
                        {"processor", proc_name.c_str()}
                    };
                } else {
                    hexrays_failure_t hf;
                    cfuncptr_t cfunc = decompile(func, &hf, DECOMP_NO_WAIT);

                    if (cfunc != nullptr) {
                        qstring pseudocode;
                        cfunc->get_pseudocode(pseudocode);

                        context["decompilation"] = {
                            {"available", true},
                            {"pseudocode", pseudocode.c_str()}
                        };
                    } else {
                        context["decompilation"] = {
                            {"available", false},
                            {
                                "note",
                                "Decompilation not available (requires Hexrays license or function cannot be decompiled)"
                            }
                        };
                    }
                }
#else
                context["decompilation"] = {
                    {"available", false},
                    {"note", "Decompilation not available (plugin built without Hexrays support)"}
                };
#endif
            }

            // Get function comments
            qstring regular_cmt;
            qstring repeatable_cmt;
            get_func_cmt(&regular_cmt, func, false);
            get_func_cmt(&repeatable_cmt, func, true);

            if (!regular_cmt.empty() || !repeatable_cmt.empty()) {
                context["comments"] = {
                    {"regular", regular_cmt.c_str()},
                    {"repeatable", repeatable_cmt.c_str()}
                };
            }

            // Get exception handling information
            tryblks_t tryblks;
            range_t func_range(start_ea, end_ea);
            size_t tryblk_count = get_tryblks(&tryblks, func_range);

            if (tryblk_count > 0) {
                json exception_info = json::object();
                exception_info["has_exception_handling"] = true;
                exception_info["tryblock_count"] = tryblk_count;

                json tryblocks = json::array();
                for (size_t i = 0; i < tryblks.size(); i++) {
                    const tryblk_t &tb = tryblks[i];

                    json tb_info = json::object();
                    tb_info["index"] = i;
                    tb_info["level"] = tb.level;

                    // Get try block range
                    json ranges = json::array();
                    for (size_t j = 0; j < tb.size(); j++) {
                        const range_t &r = tb[j];
                        ranges.push_back(json{
                            {"start", format_ea(r.start_ea)},
                            {"end", format_ea(r.end_ea)},
                            {"size", r.end_ea - r.start_ea}
                        });
                    }
                    tb_info["ranges"] = ranges;

                    if (tb.is_cpp()) {
                        tb_info["type"] = "cpp_exception";
                        const catchvec_t &catches = tb.cpp();
                        json catch_blocks = json::array();

                        for (size_t k = 0; k < catches.size(); k++) {
                            const catch_t &c = catches[k];
                            json catch_info = json::object();

                            // Catch handler ranges
                            json catch_ranges = json::array();
                            for (size_t m = 0; m < c.size(); m++) {
                                const range_t &r = c[m];
                                catch_ranges.push_back(json{
                                    {"start", format_ea(r.start_ea)},
                                    {"end", format_ea(r.end_ea)}
                                });
                            }
                            catch_info["ranges"] = catch_ranges;

                            // Type information
                            if (c.type_id == CATCH_ID_ALL) {
                                catch_info["catches"] = "catch_all";
                            } else if (c.type_id == CATCH_ID_CLEANUP) {
                                catch_info["catches"] = "cleanup_handler";
                            } else {
                                catch_info["type_id"] = c.type_id;
                            }

                            // Stack info
                            if (c.disp != -1) {
                                catch_info["stack_displacement"] = c.disp;
                            }
                            if (c.obj != -1) {
                                catch_info["exception_object_offset"] = c.obj;
                            }
                            if (c.fpreg != -1) {
                                catch_info["frame_register"] = c.fpreg;
                            }

                            catch_blocks.push_back(catch_info);
                        }
                        tb_info["catch_blocks"] = catch_blocks;

                    } else if (tb.is_seh()) {
                        tb_info["type"] = "seh_exception";
                        const seh_t &seh = tb.seh();

                        json seh_info = json::object();

                        // Handler ranges
                        json handler_ranges = json::array();
                        for (size_t m = 0; m < seh.size(); m++) {
                            const range_t &r = seh[m];
                            handler_ranges.push_back(json{
                                {"start", format_ea(r.start_ea)},
                                {"end", format_ea(r.end_ea)}
                            });
                        }
                        seh_info["handler_ranges"] = handler_ranges;

                        // Filter callback
                        if (!seh.filter.empty()) {
                            json filter_ranges = json::array();
                            for (size_t m = 0; m < seh.filter.size(); m++) {
                                const range_t &r = seh.filter[m];
                                filter_ranges.push_back(json{
                                    {"start", format_ea(r.start_ea)},
                                    {"end", format_ea(r.end_ea)}
                                });
                            }
                            seh_info["filter_ranges"] = filter_ranges;
                        } else {
                            // Filter code constant
                            if (seh.seh_code == SEH_CONTINUE) {
                                seh_info["filter_code"] = "EXCEPTION_CONTINUE_EXECUTION";
                            } else if (seh.seh_code == SEH_SEARCH) {
                                seh_info["filter_code"] = "EXCEPTION_CONTINUE_SEARCH";
                            } else if (seh.seh_code == SEH_HANDLE) {
                                seh_info["filter_code"] = "EXCEPTION_EXECUTE_HANDLER";
                            }
                        }

                        // Stack info
                        if (seh.disp != -1) {
                            seh_info["stack_displacement"] = seh.disp;
                        }
                        if (seh.fpreg != -1) {
                            seh_info["frame_register"] = seh.fpreg;
                        }

                        tb_info["seh"] = seh_info;
                    }

                    tryblocks.push_back(tb_info);
                }

                exception_info["tryblocks"] = tryblocks;
                context["exception_handling"] = exception_info;
            }

            return context;
        }
    } // anonymous namespace

    void register_tools(mcp::McpServer &server) {
        // get_function_context
        {
            mcp::ToolDefinition def;
            def.name = "get_function_context";
            def.description = "Get function context and xrefs";
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
                            "include_xrefs", {
                                {"type", "boolean"},
                                {"description", "Include xrefs"}
                            }
                        },
                        {
                            "max_depth", {
                                {"type", "number"},
                                {"description", "Max depth"}
                            }
                        },
                        {
                            "include_decompilation", {
                                {"type", "boolean"},
                                {"description", "Include decompilation"}
                            }
                        }
                    }
                },
                {"required", json::array({"address"})}
            };
            server.register_tool(def, handle_get_function_context);
        }
    }
} // namespace ida_mcp::tools::function_context
