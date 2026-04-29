#include "tools/tools.hpp"
#include <expr.hpp>
#include <diskio.hpp>

#ifdef HAS_HEXRAYS
#include <hexrays.hpp>
#include <lines.hpp>
#endif

#include <fstream>
#include <filesystem>
#include <regex>

namespace ida_mcp::tools::hexrays {
    namespace {
        // Sanitize filename - remove characters that are invalid in filenames
        std::string sanitize_filename(const std::string &name) {
            std::string result;
            result.reserve(name.size());
            for (char c: name) {
                if (std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-' || c == '.') {
                    result += c;
                } else {
                    result += '_';
                }
            }
            // Truncate if too long (max 200 chars for safety)
            if (result.size() > 200) {
                result = result.substr(0, 200);
            }
            return result;
        }
    }

    static json decompile_function(const json &params) {
#ifdef HAS_HEXRAYS
        if (!params.contains("address") || !params["address"].is_string()) {
            throw std::runtime_error("Missing required parameter: address");
        }

        auto addr = parse_ea(params["address"]);
        if (!addr.has_value()) {
            throw std::runtime_error("Invalid address");
        }

        ea_t ea = addr.value();

        // Check if hexrays is available
        if (!init_hexrays_plugin()) {
            throw std::runtime_error("Hexrays decompiler not available (check license)");
        }

        func_t *func = get_func(ea);
        if (func == nullptr) {
            throw std::runtime_error("Address is not in a function");
        }

        if ((func->flags & FUNC_THUNK) != 0) {
            qstring fname;
            get_func_name(&fname, func->start_ea);

            ea_t fptr = BADADDR;
            ea_t target = calc_thunk_func_target(func, &fptr);
            qstring tname;
            if (target != BADADDR)
                get_func_name(&tname, target);

            qstring import_name;
            if (fptr != BADADDR) {
                qstring slot_name;
                if (get_name(&slot_name, fptr) > 0) {
                    import_name = slot_name;
                }
                if (target == BADADDR) {
                    ea_t indirect_target = get_qword(fptr);
                    if (is_loaded(indirect_target)) {
                        target = indirect_target;
                        if (tname.empty())
                            get_func_name(&tname, indirect_target);
                    }
                }
            }

            qstring disasm;
            ea_t addr = func->start_ea;
            int instr_count = 0;
            while (addr < func->end_ea && addr != BADADDR && instr_count < 16) {
                qstring line;
                generate_disasm_line(&line, addr, GENDSM_REMOVE_TAGS);
                disasm.cat_sprnt("//   %s %s\n", format_ea(addr).c_str(), line.c_str());
                ea_t next = next_head(addr, func->end_ea);
                if (next == BADADDR || next <= addr) break;
                addr = next;
                ++instr_count;
            }

            qstring sig_str;
            tinfo_t target_tif;
            if (target != BADADDR && get_tinfo(&target_tif, target)) {
                target_tif.print(&sig_str);
            }

            qstring stub;
            stub.sprnt(
                "// ============================================================\n"
                "// THUNK / TRAMPOLINE\n"
                "// ============================================================\n"
                "// Address:         %s\n"
                "// Name:            %s\n"
                "// Size:            %llu bytes (%d instructions)\n"
                "// Disassembly:\n"
                "%s"
                "//\n"
                "// Resolved target: %s\n"
                "// Target address:  %s\n"
                "// GOT/IAT slot:    %s\n"
                "// Slot symbol:     %s\n"
                "// Target type:     %s\n"
                "// ============================================================\n"
                "\n"
                "%s %s(/* see target signature */)\n"
                "{\n"
                "    // Tail-call to %s via %s indirection\n"
                "    return %s(/* forwarded args */);\n"
                "}\n",
                format_ea(ea).c_str(),
                fname.empty() ? "<anonymous>" : fname.c_str(),
                (unsigned long long)func->size(),
                instr_count,
                disasm.empty() ? "//   <empty>\n" : disasm.c_str(),
                tname.empty() ? "<unresolved>" : tname.c_str(),
                target != BADADDR ? format_ea(target).c_str() : "BADADDR",
                fptr != BADADDR ? format_ea(fptr).c_str() : "(none)",
                import_name.empty() ? "<none>" : import_name.c_str(),
                sig_str.empty() ? "<no type info>" : sig_str.c_str(),
                sig_str.empty() ? "void" : "/* see target sig */",
                fname.empty() ? "thunk_func" : fname.c_str(),
                tname.empty() ? "<unresolved target>" : tname.c_str(),
                fptr != BADADDR ? "GOT/IAT" : "direct jump",
                tname.empty() ? "/* unresolved */" : tname.c_str());

            return json{
                {"address",              format_ea(ea)},
                {"function_name",        fname.c_str()},
                {"pseudocode",           stub.c_str()},
                {"signature",            sig_str.empty() ? "void(void)" : sig_str.c_str()},
                {"decompilation_method", "thunk_disasm"},
                {"is_thunk",             true},
                {"thunk_size_bytes",     (unsigned long long)func->size()},
                {"thunk_instr_count",    instr_count},
                {"thunk_target",         target != BADADDR ? format_ea(target) : ""},
                {"thunk_target_name",    tname.c_str()},
                {"thunk_got_slot",       fptr != BADADDR ? format_ea(fptr) : ""},
                {"thunk_import_name",    import_name.c_str()},
                {"lvars_count",          0}
            };
        }

        std::string skip_reason;
        if (ida_mcp::is_go_pathological_func(func, &skip_reason)) {
            throw std::runtime_error(
                "Skipped to avoid Hex-Rays infinite loop (IDA 9.3sp1 golang.so bug): " + skip_reason);
        }

        hexrays_failure_t hf;
        cfuncptr_t cfunc = decompile(func, &hf, DECOMP_NO_WAIT);

        if (cfunc == nullptr) {
            extlang_object_t python = find_extlang_by_name("Python");
            if (python != nullptr) {
                char tmpname[QMAXPATH];
                qtmpnam(tmpname, sizeof(tmpname));
                qstring tmp_json_path = tmpname;
                tmp_json_path.append(".json");

                qstring py_code;
                py_code.sprnt(
                    "import ida_hexrays as hr, ida_funcs, ida_bytes, ida_lines, ida_kernwin, json\n"
                    "ea = 0x%llX\n"
                    "func = ida_funcs.get_func(ea)\n"
                    "r = {'tier2': False, 'tier3': False}\n"
                    "\n"
                    "ida_kernwin.create_undo_point(b'mcp_decompile_tier2_patch')\n"
                    "\n"
                    "patches = []\n"
                    "addr = func.start_ea\n"
                    "while addr < func.end_ea:\n"
                    "    dw = ida_bytes.get_dword(addr)\n"
                    "    if (dw & 0xFFFF0000) == 0xD71F0000 or (dw & 0xFFFF0000) == 0xD61F0000:\n"
                    "        patches.append((addr, dw))\n"
                    "        ida_bytes.patch_dword(addr, 0xD65F03C0)\n"
                    "    elif ida_bytes.get_byte(addr) == 0xFF:\n"
                    "        modrm = ida_bytes.get_byte(addr + 1)\n"
                    "        reg = (modrm >> 3) & 7\n"
                    "        if reg == 4 or reg == 2:\n"
                    "            sz = 2\n"
                    "            if (modrm & 0xC0) == 0x40: sz = 3\n"
                    "            elif (modrm & 0xC0) == 0x80: sz = 6\n"
                    "            orig = [ida_bytes.get_byte(addr + i) for i in range(sz)]\n"
                    "            patches.append((addr, orig))\n"
                    "            ida_bytes.patch_byte(addr, 0xC3)\n"
                    "            for i in range(1, sz):\n"
                    "                ida_bytes.patch_byte(addr + i, 0x90)\n"
                    "    addr += 4 if func.start_ea > 0x100000000 else 1\n"
                    "\n"
                    "try:\n"
                    "    if patches:\n"
                    "        try:\n"
                    "            cfunc = hr.decompile(ea)\n"
                    "            if cfunc:\n"
                    "                sv = cfunc.get_pseudocode()\n"
                    "                lines = []\n"
                    "                for i in range(len(sv)):\n"
                    "                    lines.append(ida_lines.tag_remove(sv[i].line))\n"
                    "                r = {'tier2': True, 'pseudo': chr(10).join(lines), 'patched': len(patches)}\n"
                    "        except: pass\n"
                    "finally:\n"
                    "    for p in patches:\n"
                    "        try:\n"
                    "            if isinstance(p[1], int):\n"
                    "                ida_bytes.patch_dword(p[0], p[1])\n"
                    "            else:\n"
                    "                for i, b in enumerate(p[1]):\n"
                    "                    ida_bytes.patch_byte(p[0] + i, b)\n"
                    "        except: pass\n"
                    "\n"
                    "if not r.get('tier2'):\n"
                    "    hf = hr.hexrays_failure_t()\n"
                    "    mbr = hr.mba_ranges_t(func)\n"
                    "    mba = hr.gen_microcode(mbr, hf, None, hr.DECOMP_WARNINGS, hr.MMAT_LOCOPT)\n"
                    "    if mba:\n"
                    "        lines = []\n"
                    "        for i in range(mba.qty):\n"
                    "            blk = mba.get_mblock(i)\n"
                    "            if blk.start == 0xffffffffffffffff: continue\n"
                    "            insn = blk.head\n"
                    "            while insn:\n"
                    "                lines.append(ida_lines.tag_remove(insn._print()))\n"
                    "                insn = insn.next\n"
                    "        r = {'tier3': True, 'pseudo': chr(10).join(lines), 'blocks': mba.qty}\n"
                    "\n"
                    "with open(%s, 'w') as f: json.dump(r, f)\n",
                    (uint64)ea, json(tmp_json_path.c_str()).dump().c_str());

                qstring errbuf;
                python->eval_snippet(py_code.c_str(), &errbuf);

                qstring json_str;
                FILE *fp = qfopen(tmp_json_path.c_str(), "r");
                if (fp) {
                    char buf[65536];
                    ssize_t n;
                    while ((n = qfread(fp, buf, sizeof(buf))) > 0)
                        json_str.append(buf, static_cast<size_t>(n));
                    qfclose(fp);
                }
                qunlink(tmp_json_path.c_str());

                json fb;
                if (!json_str.empty()) {
                    try { fb = json::parse(json_str.c_str()); } catch (...) {}
                }

                if (fb.is_object() && fb.value("tier2", false)) {
                    qstring func_name;
                    get_func_name(&func_name, func->start_ea);
                    return json{
                        {"address", format_ea(ea)},
                        {"function_name", func_name.c_str()},
                        {"pseudocode", fb.value("pseudo", "")},
                        {"signature", nullptr},
                        {"decompilation_method", "patched_decompile"},
                        {"patches_applied", fb.value("patched", 0)},
                        {"lvars_count", 0}
                    };
                }

                if (fb.is_object() && fb.value("tier3", false)) {
                    qstring func_name;
                    get_func_name(&func_name, func->start_ea);
                    return json{
                        {"address", format_ea(ea)},
                        {"function_name", func_name.c_str()},
                        {"pseudocode", fb.value("pseudo", "")},
                        {"signature", nullptr},
                        {"decompilation_method", "microcode_lift"},
                        {"microcode_blocks", fb.value("blocks", 0)},
                        {"lvars_count", 0}
                    };
                }
            }

            qstring err_str = hf.desc();
            throw std::runtime_error(std::string("Decompilation failed: ") + err_str.c_str());
        }

        const strvec_t &sv = cfunc->get_pseudocode();
        qstring pseudocode;
        for (size_t i = 0; i < sv.size(); i++) {
            if (i > 0) pseudocode.append("\n");
            qstring clean_line;
            tag_remove(&clean_line, sv[i].line);
            pseudocode.append(clean_line);
        }

        tinfo_t func_type;
        qstring signature;
        if (cfunc->get_func_type(&func_type)) {
            qstring raw_sig;
            func_type.print(&raw_sig);
            tag_remove(&signature, raw_sig);
        }

        // Get local variables count
        lvars_t *lvars = cfunc->get_lvars();
        size_t lvars_count = lvars != nullptr ? lvars->size() : 0;

        return json{
            {"address", format_ea(ea)},
            {"function_name", get_function_name(func)},
            {"pseudocode", pseudocode.c_str()},
            {"signature", signature.c_str()},
            {"lvars_count", lvars_count}
        };
#else
        throw std::runtime_error("Hexrays support not compiled in");
#endif
    }

    static json export_all_decompiled(const json &params) {
#ifdef HAS_HEXRAYS
        // Check if hexrays is available
        if (!init_hexrays_plugin()) {
            throw std::runtime_error("Hexrays decompiler not available (check license)");
        }

        // Get output directory - default to current working directory
        std::string output_dir = ".";
        if (params.contains("output_dir") && params["output_dir"].is_string()) {
            output_dir = params["output_dir"].get<std::string>();
        }

        // Create output directory securely
        std::filesystem::path out_path(output_dir);
        
        // Security: Use weakly_canonical for path normalization, then check if safe
        // Note: weakly_canonical works on non-existent paths unlike canonical()
        std::error_code ec;
        out_path = std::filesystem::weakly_canonical(out_path, ec);
        if (ec) {
            throw std::runtime_error("Invalid output directory path: " + ec.message());
        }
        
        // Ensure the path is absolute after canonicalization
        if (!out_path.is_absolute()) {
            out_path = std::filesystem::absolute(out_path, ec);
            if (ec) {
                throw std::runtime_error("Cannot resolve absolute path: " + ec.message());
            }
        }
        
        // Create directory with restrictive permissions if it doesn't exist
        if (!std::filesystem::exists(out_path)) {
            // Create with default permissions (umask applies)
            std::filesystem::create_directories(out_path, ec);
            if (ec) {
                throw std::runtime_error("Failed to create output directory: " + ec.message());
            }
        } else if (!std::filesystem::is_directory(out_path)) {
            throw std::runtime_error("Output path exists but is not a directory");
        }

        std::optional<std::regex> name_filter;
        if (params.contains("name_filter") && params["name_filter"].is_string()) {
            std::string pattern = params["name_filter"].get<std::string>();
            if (pattern.size() > 512) {
                throw std::runtime_error(
                    "name_filter too long (max 512 chars) - suspected ReDoS attempt");
            }
            if (!pattern.empty()) {
                try {
                    name_filter = std::regex(
                        pattern, std::regex::ECMAScript | std::regex::icase
                                 | std::regex::nosubs | std::regex::optimize);
                } catch (const std::regex_error &e) {
                    throw std::runtime_error(
                        std::string("Invalid name_filter regex: ") + e.what());
                }
            }
        }

        // Optional: skip library functions
        bool skip_library = true;
        if (params.contains("skip_library") && params["skip_library"].is_boolean()) {
            skip_library = params["skip_library"].get<bool>();
        }

        // Optional: skip thunks
        bool skip_thunks = true;
        if (params.contains("skip_thunks") && params["skip_thunks"].is_boolean()) {
            skip_thunks = params["skip_thunks"].get<bool>();
        }

        // Statistics
        size_t total_functions = get_func_qty();
        size_t exported_count = 0;
        size_t skipped_count = 0;
        size_t failed_count = 0;
        json failed_functions = json::array();

        // Iterate through all functions
        for (size_t i = 0; i < total_functions; i++) {
            func_t *func = getn_func(i);
            if (func == nullptr) {
                skipped_count++;
                continue;
            }

            // Skip library functions if requested
            if (skip_library && (func->flags & FUNC_LIB) != 0) {
                skipped_count++;
                continue;
            }

            // Skip thunks if requested
            if (skip_thunks && (func->flags & FUNC_THUNK) != 0) {
                skipped_count++;
                continue;
            }

            // Get function name
            std::string func_name = get_function_name(func);

            // Apply name filter if specified
            if (name_filter.has_value()) {
                if (!std::regex_search(func_name, name_filter.value())) {
                    skipped_count++;
                    continue;
                }
            }

            if (ida_mcp::is_go_pathological_func(func)) {
                skipped_count++;
                continue;
            }

            // Try to decompile
            hexrays_failure_t hf;
            cfuncptr_t cfunc = decompile(func, &hf, DECOMP_NO_WAIT);

            if (cfunc == nullptr) {
                qstring err_str = hf.desc();
                failed_count++;
                if (failed_functions.size() < 100) {
                    failed_functions.push_back(json{
                        {"name", func_name},
                        {"address", format_ea(func->start_ea)},
                        {"error", err_str.c_str()}
                    });
                }
                continue;
            }

            const strvec_t &sv = cfunc->get_pseudocode();
            qstring pseudocode;
            for (size_t j = 0; j < sv.size(); j++) {
                if (j > 0) pseudocode.append("\n");
                qstring clean_line;
                tag_remove(&clean_line, sv[j].line);
                pseudocode.append(clean_line);
            }

            tinfo_t func_type;
            qstring signature;
            if (cfunc->get_func_type(&func_type)) {
                qstring raw_sig;
                func_type.print(&raw_sig);
                tag_remove(&signature, raw_sig);
            }

            // Build file content with header comment
            std::string content;
            content += "// Function: " + func_name + "\n";
            content += "// Address: " + format_ea(func->start_ea) + "\n";
            content += "// Size: " + std::to_string(func->end_ea - func->start_ea) + " bytes\n";
            content += "//\n";
            if (!signature.empty()) {
                content += "// Signature: ";
                content += signature.c_str();
                content += "\n";
            }
            content += "\n";
            content += pseudocode.c_str();

            // Generate filename: address_name.c
            std::string filename = format_ea(func->start_ea) + "_" + sanitize_filename(func_name) + ".c";
            std::filesystem::path file_path = out_path / filename;

            // Security: Verify the resolved path is still within our output directory
            // This prevents symlink attacks where filename could escape the directory
            std::error_code write_ec;
            auto resolved_file = std::filesystem::weakly_canonical(file_path, write_ec);
            
            // Ensure out_path ends with separator for proper prefix matching
            // This prevents /tmp/out matching /tmp/out_evil
            auto out_path_str = out_path.string();
            if (!out_path_str.empty() && out_path_str.back() != std::filesystem::path::preferred_separator) {
                out_path_str += std::filesystem::path::preferred_separator;
            }
            auto resolved_str = resolved_file.string();
            
            // Check: resolved path must start with out_path (including trailing separator)
            bool path_escape = write_ec || 
                               resolved_str.size() < out_path_str.size() ||
                               resolved_str.compare(0, out_path_str.size(), out_path_str) != 0;
            
            if (path_escape) {
                failed_count++;
                if (failed_functions.size() < 100) {
                    failed_functions.push_back(json{
                        {"name", func_name},
                        {"address", format_ea(func->start_ea)},
                        {"error", "Path escape attempt detected"}
                    });
                }
                continue;
            }

            // Write to file
            std::ofstream ofs(file_path, std::ios::out | std::ios::trunc);
            if (ofs.is_open()) {
                ofs << content;
                ofs.close();
                exported_count++;
            } else {
                failed_count++;
                if (failed_functions.size() < 100) {
                    failed_functions.push_back(json{
                        {"name", func_name},
                        {"address", format_ea(func->start_ea)},
                        {"error", "Failed to write file: " + file_path.string()}
                    });
                }
            }
        }

        json result = json{
            {"output_dir", std::filesystem::absolute(out_path).string()},
            {"total_functions", total_functions},
            {"exported_count", exported_count},
            {"skipped_count", skipped_count},
            {"failed_count", failed_count}
        };

        if (!failed_functions.empty()) {
            result["failed_functions"] = failed_functions;
        }

        return result;
#else
        throw std::runtime_error("Hexrays support not compiled in");
#endif
    }

    void register_tools(mcp::McpServer &server) {
        // decompile_function tool
        {
            mcp::ToolDefinition def;
            def.name = "decompile_function";
            def.description = "Decompile function to pseudocode";
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
            server.register_tool(def, decompile_function);
        }

        // export_all_decompiled tool
        {
            mcp::ToolDefinition def;
            def.name = "export_all_decompiled";
            def.description = "Export all decompiled functions to individual .c files in a directory. "
                    "Each file contains the pseudocode with a header showing function name, address, and signature.";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "output_dir", {
                                {"type", "string"},
                                {
                                    "description",
                                    "Output directory path. Defaults to current working directory if not specified."
                                }
                            }
                        },
                        {
                            "name_filter", {
                                {"type", "string"},
                                {
                                    "description",
                                    "Optional regex pattern to filter functions by name. Only functions matching this pattern will be exported."
                                }
                            }
                        },
                        {
                            "skip_library", {
                                {"type", "boolean"},
                                {"description", "Skip library functions (default: true)"}
                            }
                        },
                        {
                            "skip_thunks", {
                                {"type", "boolean"},
                                {"description", "Skip thunk functions (default: true)"}
                            }
                        }
                    }
                }
            };
            server.register_tool(def, export_all_decompiled);
        }
        {
            mcp::ToolDefinition def;
            def.name = "force_decompile";
            def.description =
                "Force-decompile a function that Hex-Rays refuses to decompile. "
                "Falls back to microcode lifting (MMAT_LOCOPT) when normal decompilation fails. "
                "Works on PAC-obfuscated, indirect-jump, and other resistant functions.";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Function address (hex)"}}}
                }},
                {"required", json::array({"address"})}
            };

            server.register_tool(def, [](const json &params) -> json {
                auto ea_opt = parse_ea(params["address"]);
                if (!ea_opt) throw std::runtime_error("Invalid address");
                ea_t ea = ea_opt.value();

                func_t *func = get_func(ea);
                if (!func) throw std::runtime_error("No function at " + format_ea(ea));

                qstring fname;
                get_func_name(&fname, func->start_ea);

                extlang_object_t python = find_extlang_by_name("Python");
                if (python == nullptr)
                    throw std::runtime_error("IDAPython not available");

                char tmpname[QMAXPATH];
                qtmpnam(tmpname, sizeof(tmpname));
                qstring tmp_json_path = tmpname;
                tmp_json_path.append(".json");

                qstring py_code;
                py_code.sprnt(
                    "import ida_hexrays as hr\n"
                    "import ida_funcs\n"
                    "import json\n"
                    "\n"
                    "ea = 0x%llX\n"
                    "func = ida_funcs.get_func(ea)\n"
                    "result = {}\n"
                    "\n"
                    "try:\n"
                    "    cfunc = hr.decompile(ea)\n"
                    "    if cfunc:\n"
                    "        result = {'method': 'hexrays', 'pseudocode': str(cfunc)}\n"
                    "    else:\n"
                    "        raise Exception('returned None')\n"
                    "except:\n"
                    "    hf = hr.hexrays_failure_t()\n"
                    "    mbr = hr.mba_ranges_t(func)\n"
                    "    mba = hr.gen_microcode(mbr, hf, None, hr.DECOMP_WARNINGS, hr.MMAT_LOCOPT)\n"
                    "    if mba:\n"
                    "        lines = []\n"
                    "        for i in range(mba.qty):\n"
                    "            blk = mba.get_mblock(i)\n"
                    "            if blk.start == 0xffffffffffffffff: continue\n"
                    "            insn = blk.head\n"
                    "            while insn:\n"
                    "                lines.append(insn._print())\n"
                    "                insn = insn.next\n"
                    "        result = {'method': 'microcode', 'blocks': mba.qty, 'microcode': '\\n'.join(lines)}\n"
                    "    else:\n"
                    "        result = {'method': 'failed', 'error': hf.desc()}\n"
                    "\n"
                    "with open(%s, 'w') as f:\n"
                    "    json.dump(result, f)\n",
                    (uint64)ea, json(tmp_json_path.c_str()).dump().c_str());

                qstring errbuf;
                python->eval_snippet(py_code.c_str(), &errbuf);

                qstring json_str;
                FILE *fp = qfopen(tmp_json_path.c_str(), "r");
                if (fp) {
                    char buf[4096];
                    ssize_t n;
                    while ((n = qfread(fp, buf, sizeof(buf))) > 0)
                        json_str.append(buf, static_cast<size_t>(n));
                    qfclose(fp);
                }
                qunlink(tmp_json_path.c_str());

                json py_result;
                if (!json_str.empty()) {
                    try { py_result = json::parse(json_str.c_str()); } catch (...) {}
                }

                json result;
                result["address"] = format_ea(func->start_ea);
                result["function"] = fname.c_str();
                result["size"] = func->size();

                if (py_result.is_object() && py_result.contains("pseudocode")) {
                    result["method"] = "hexrays";
                    result["pseudocode"] = py_result["pseudocode"];
                } else if (py_result.is_object() && py_result.contains("microcode")) {
                    result["method"] = "microcode_lift";
                    result["blocks"] = py_result.value("blocks", 0);
                    result["microcode"] = py_result["microcode"];
                } else {
                    result["method"] = "failed";
                    if (py_result.is_object())
                        result["error"] = py_result.value("error", errbuf.c_str());
                    else
                        result["error"] = errbuf.empty()
                            ? std::string("decompile failed and python fallback produced no output")
                            : std::string(errbuf.c_str());
                }

                return result;
            });
        }
    }
} // namespace ida_mcp::tools::hexrays
