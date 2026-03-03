#include "tools/tools.hpp"

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

        // Get function
        func_t *func = get_func(ea);
        if (func == nullptr) {
            throw std::runtime_error("Address is not in a function");
        }

        // Decompile
        hexrays_failure_t hf;
        cfuncptr_t cfunc = decompile(func, &hf, DECOMP_NO_WAIT);

        if (cfunc == nullptr) {
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
            // Security: reject path traversal attempts
            if (output_dir.find("..") != std::string::npos) {
                throw std::runtime_error("Path traversal not allowed in output_dir");
            }
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

        // Optional: filter by name pattern (regex)
        std::optional<std::regex> name_filter;
        if (params.contains("name_filter") && params["name_filter"].is_string()) {
            std::string pattern = params["name_filter"].get<std::string>();
            if (!pattern.empty()) {
                name_filter = std::regex(pattern, std::regex::ECMAScript | std::regex::icase);
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
            auto out_path_str = out_path.string();
            auto resolved_str = resolved_file.string();
            if (write_ec || resolved_str.compare(0, out_path_str.size(), out_path_str) != 0) {
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
    }
} // namespace ida_mcp::tools::hexrays
