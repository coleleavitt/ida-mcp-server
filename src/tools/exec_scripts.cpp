#include "tools/tools.hpp"
#include <expr.hpp>
#include <idp.hpp>

namespace ida_mcp::tools::exec_scripts {
    namespace {
        json idc_value_to_json(const idc_value_t &v);

        std::string python_literal(const std::string &value) {
            return json(value).dump();
        }

        json parse_python_json_result(extlang_object_t python, const char *name,
                                      qstring *errbuf) {
            idc_value_t result;
            if (!python->eval_expr(&result, BADADDR, name, errbuf)) {
                return json{
                    {"success", false},
                    {"isError", true},
                    {"error", errbuf->c_str()},
                    {"language", "python"}
                };
            }

            if (result.vtype != VT_STR) {
                return json{
                    {"success", false},
                    {"isError", true},
                    {"error", "IDAPython result bridge did not return a string"},
                    {"result", idc_value_to_json(result)},
                    {"language", "python"}
                };
            }

            try {
                return json::parse(result.c_str());
            } catch (const json::parse_error &e) {
                return json{
                    {"success", false},
                    {"isError", true},
                    {"error", std::string("Failed to parse IDAPython result bridge JSON: ") + e.what()},
                    {"raw", result.c_str()},
                    {"language", "python"}
                };
            }
        }

        // Helper to convert idc_value_t to JSON
        json idc_value_to_json(const idc_value_t &v) {
            switch (v.vtype) {
                case VT_LONG:
                    return json{
                        {"type", "long"},
                        {"value", static_cast<int64_t>(v.num)}
                    };
                case VT_INT64:
                    return json{
                        {"type", "int64"},
                        {"value", static_cast<int64_t>(v.i64)}
                    };
                case VT_STR:
                    return json{
                        {"type", "string"},
                        {"value", v.c_str()}
                    };
                case VT_FLOAT: {
                    double fval = 0.0;
                    v.e.to_double(&fval);
                    return json{
                        {"type", "float"},
                        {"value", fval}
                    };
                }
                case VT_WILD:
                    return json{
                        {"type", "void"},
                        {"value", nullptr}
                    };
                default:
                    return json{
                        {"type", "unknown"},
                        {"value", nullptr}
                    };
            }
        }

        // Evaluate expression using IDC interpreter
        // Note: Despite the generic name, this uses eval_idc_expr which only supports IDC.
        // For Python support, use IDAPython's run_python_statement() via a separate tool.
        json handle_eval_expr(const json &params) {
            std::string expression = params["expression"].get<std::string>();
            ea_t ea = BADADDR;

            if (params.contains("address") && !params["address"].is_null()) {
                std::string addr_str = params["address"].get<std::string>();
                if (addr_str != "0") {
                    auto addr_opt = parse_ea(addr_str);
                    if (addr_opt.has_value()) {
                        ea = addr_opt.value();
                    }
                }
            }

            // Evaluate the expression using IDC interpreter
            idc_value_t result;
            qstring err_msg;

            bool success = eval_idc_expr(&result, ea, expression.c_str(), &err_msg);

            if (!success) {
                return json{
                    {"success", false},
                    {"error", err_msg.c_str()},
                    {"expression", expression},
                    {"language", "idc"}
                };
            }

            return json{
                {"success", true},
                {"expression", expression},
                {"result", idc_value_to_json(result)},
                {"language", "idc"}
            };
        }

        // Alias for handle_eval_expr - kept for API compatibility
        // Both tools use the same IDC interpreter underneath
        json handle_eval_idc(const json &params) {
            return handle_eval_expr(params);
        }

        // Execute IDC code snippet
        json handle_exec_snippet(const json &params) {
            std::string code = params["code"].get<std::string>();
            ea_t ea = BADADDR;

            if (params.contains("address") && !params["address"].is_null()) {
                std::string addr_str = params["address"].get<std::string>();
                if (addr_str != "0") {
                    auto addr_opt = parse_ea(addr_str);
                    if (addr_opt.has_value()) {
                        ea = addr_opt.value();
                    }
                }
            }

            // Execute the code snippet
            idc_value_t result;
            qstring err_msg;

            bool success = eval_idc_expr(&result, ea, code.c_str(), &err_msg);

            if (!success) {
                return json{
                    {"success", false},
                    {"error", err_msg.c_str()},
                    {"code", code}
                };
            }

            return json{
                {"success", true},
                {"code", code},
                {"result", idc_value_to_json(result)}
            };
        }

        // Compile IDC code
        json handle_compile_idc(const json &params) {
            std::string code = params["code"].get<std::string>();

            // Try to compile/execute the IDC code
            idc_value_t result;
            qstring err_msg;

            bool success = eval_idc_expr(&result, BADADDR, code.c_str(), &err_msg);

            if (!success) {
                return json{
                    {"success", false},
                    {"error", err_msg.c_str()},
                    {"code", code},
                    {"note", "Code compilation/execution failed"}
                };
            }

            return json{
                {"success", true},
                {"code", code},
                {"result", idc_value_to_json(result)},
                {"note", "Code executed successfully"}
            };
        }

        // Call IDC function
        json handle_call_idc_func(const json &params) {
            std::string func_name = params["function_name"].get<std::string>();

            // Build function call expression
            std::string expression = func_name + "()";

            // Execute the function call
            idc_value_t result;
            qstring err_msg;

            bool success = eval_idc_expr(&result, BADADDR, expression.c_str(), &err_msg);

            if (!success) {
                return json{
                    {"success", false},
                    {"error", err_msg.c_str()},
                    {"function_name", func_name}
                };
            }

            return json{
                {"success", true},
                {"function_name", func_name},
                {"result", idc_value_to_json(result)}
            };
        }
        json handle_run_python(const json &params) {
            std::string code = params["code"].get<std::string>();

            extlang_object_t python = find_extlang_by_name("Python");
            if (python == nullptr)
                throw std::runtime_error("Python extlang not available (IDAPython not loaded)");

            std::string wrapped =
                "import io as __ida_mcp_io, json as __ida_mcp_json, sys as __ida_mcp_sys, traceback as __ida_mcp_traceback\n"
                "__ida_mcp_stdout = __ida_mcp_io.StringIO()\n"
                "__ida_mcp_stderr = __ida_mcp_io.StringIO()\n"
                "__ida_mcp_old_stdout = __ida_mcp_sys.stdout\n"
                "__ida_mcp_old_stderr = __ida_mcp_sys.stderr\n"
                "__ida_mcp_success = True\n"
                "__ida_mcp_error = None\n"
                "try:\n"
                "    __ida_mcp_sys.stdout = __ida_mcp_stdout\n"
                "    __ida_mcp_sys.stderr = __ida_mcp_stderr\n"
                "    exec(" + python_literal(code) + ", globals(), globals())\n"
                "except BaseException:\n"
                "    __ida_mcp_success = False\n"
                "    __ida_mcp_error = __ida_mcp_traceback.format_exc()\n"
                "finally:\n"
                "    __ida_mcp_sys.stdout = __ida_mcp_old_stdout\n"
                "    __ida_mcp_sys.stderr = __ida_mcp_old_stderr\n"
                "__ida_mcp_last_result = __ida_mcp_json.dumps({\n"
                "    'success': __ida_mcp_success,\n"
                "    'isError': not __ida_mcp_success,\n"
                "    'stdout': __ida_mcp_stdout.getvalue(),\n"
                "    'stderr': __ida_mcp_stderr.getvalue(),\n"
                "    'error': __ida_mcp_error,\n"
                "    'code': " + python_literal(code) + ",\n"
                "    'language': 'python'\n"
                "})\n";

            qstring errbuf;
            bool ok = python->eval_snippet(wrapped.c_str(), &errbuf);

            if (!ok) {
                return json{
                    {"success", false},
                    {"isError", true},
                    {"error", errbuf.c_str()},
                    {"code", code},
                    {"language", "python"}
                };
            }

            return parse_python_json_result(python, "__ida_mcp_last_result", &errbuf);
        }

        json handle_run_python_expr(const json &params) {
            std::string expression = params["expression"].get<std::string>();

            extlang_object_t python = find_extlang_by_name("Python");
            if (python == nullptr)
                throw std::runtime_error("Python extlang not available (IDAPython not loaded)");

            std::string wrapped =
                "import io as __ida_mcp_io, json as __ida_mcp_json, sys as __ida_mcp_sys, traceback as __ida_mcp_traceback\n"
                "__ida_mcp_stdout = __ida_mcp_io.StringIO()\n"
                "__ida_mcp_stderr = __ida_mcp_io.StringIO()\n"
                "__ida_mcp_old_stdout = __ida_mcp_sys.stdout\n"
                "__ida_mcp_old_stderr = __ida_mcp_sys.stderr\n"
                "__ida_mcp_success = True\n"
                "__ida_mcp_error = None\n"
                "__ida_mcp_value = None\n"
                "__ida_mcp_value_json = None\n"
                "__ida_mcp_value_repr = None\n"
                "__ida_mcp_value_type = None\n"
                "try:\n"
                "    __ida_mcp_sys.stdout = __ida_mcp_stdout\n"
                "    __ida_mcp_sys.stderr = __ida_mcp_stderr\n"
                "    __ida_mcp_value = eval(" + python_literal(expression) + ", globals(), globals())\n"
                "    __ida_mcp_value_type = type(__ida_mcp_value).__name__\n"
                "    __ida_mcp_value_repr = repr(__ida_mcp_value)\n"
                "    try:\n"
                "        __ida_mcp_value_json = __ida_mcp_value\n"
                "        __ida_mcp_json.dumps(__ida_mcp_value_json)\n"
                "    except TypeError:\n"
                "        __ida_mcp_value_json = None\n"
                "except BaseException:\n"
                "    __ida_mcp_success = False\n"
                "    __ida_mcp_error = __ida_mcp_traceback.format_exc()\n"
                "finally:\n"
                "    __ida_mcp_sys.stdout = __ida_mcp_old_stdout\n"
                "    __ida_mcp_sys.stderr = __ida_mcp_old_stderr\n"
                "__ida_mcp_last_expr_result = __ida_mcp_json.dumps({\n"
                "    'success': __ida_mcp_success,\n"
                "    'isError': not __ida_mcp_success,\n"
                "    'stdout': __ida_mcp_stdout.getvalue(),\n"
                "    'stderr': __ida_mcp_stderr.getvalue(),\n"
                "    'error': __ida_mcp_error,\n"
                "    'expression': " + python_literal(expression) + ",\n"
                "    'result': {\n"
                "        'type': __ida_mcp_value_type,\n"
                "        'repr': __ida_mcp_value_repr,\n"
                "        'value': __ida_mcp_value_json\n"
                "    },\n"
                "    'language': 'python'\n"
                "})\n";

            qstring errbuf;
            bool ok = python->eval_snippet(wrapped.c_str(), &errbuf);

            if (!ok) {
                return json{
                    {"success", false},
                    {"isError", true},
                    {"error", errbuf.c_str()},
                    {"expression", expression},
                    {"language", "python"}
                };
            }

            return parse_python_json_result(python, "__ida_mcp_last_expr_result", &errbuf);
        }

    } // anonymous namespace

    void register_tools(mcp::McpServer &server) {
        // eval_expr
        {
            mcp::ToolDefinition def;
            def.name = "eval_expr";
            def.description = "Evaluate expression (Python/IDC)";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "expression", {
                                {"type", "string"},
                                {"description", "Expression to evaluate"}
                            }
                        },
                        {
                            "address", {
                                {"type", "string"},
                                {"description", "Hex address context"},
                                {"default", "0"}
                            }
                        }
                    }
                },
                {"required", json::array({"expression"})}
            };
            server.register_tool(def, handle_eval_expr);
        }

        // eval_idc
        {
            mcp::ToolDefinition def;
            def.name = "eval_idc";
            def.description = "Evaluate IDC expression only";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "expression", {
                                {"type", "string"},
                                {"description", "IDC expression"}
                            }
                        },
                        {
                            "address", {
                                {"type", "string"},
                                {"description", "Hex address context"},
                                {"default", "0"}
                            }
                        }
                    }
                },
                {"required", json::array({"expression"})}
            };
            server.register_tool(def, handle_eval_idc);
        }

        // exec_snippet
        {
            mcp::ToolDefinition def;
            def.name = "exec_snippet";
            def.description = "Execute IDC code snippet";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "code", {
                                {"type", "string"},
                                {"description", "IDC code snippet"}
                            }
                        },
                        {
                            "address", {
                                {"type", "string"},
                                {"description", "Hex address context"},
                                {"default", "0"}
                            }
                        }
                    }
                },
                {"required", json::array({"code"})}
            };
            server.register_tool(def, handle_exec_snippet);
        }

        // compile_idc
        {
            mcp::ToolDefinition def;
            def.name = "compile_idc";
            def.description = "Compile IDC function definitions";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "code", {
                                {"type", "string"},
                                {"description", "IDC code"}
                            }
                        }
                    }
                },
                {"required", json::array({"code"})}
            };
            server.register_tool(def, handle_compile_idc);
        }

        // run_python
        {
            mcp::ToolDefinition def;
            def.name = "run_python";
            def.description =
                "Execute Python code via IDAPython. Has full access to ida_*, idautils, idc, "
                "ida_hexrays, ida_nalt, etc. Use print() to return output.";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"code", {{"type", "string"}, {"description", "Python code to execute"}}}
                }},
                {"required", json::array({"code"})}
            };
            server.register_tool(def, handle_run_python);
        }

        // run_python_expr
        {
            mcp::ToolDefinition def;
            def.name = "run_python_expr";
            def.description =
                "Evaluate a Python expression and return the result. "
                "For statements/multi-line code, use run_python instead.";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"expression", {{"type", "string"}, {"description", "Python expression"}}}
                }},
                {"required", json::array({"expression"})}
            };
            server.register_tool(def, handle_run_python_expr);
        }

        // call_idc_func
        {
            mcp::ToolDefinition def;
            def.name = "call_idc_func";
            def.description = "Call IDC function by name";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {
                            "function_name", {
                                {"type", "string"},
                                {"description", "Name of IDC function to call"}
                            }
                        }
                    }
                },
                {"required", json::array({"function_name"})}
            };
            server.register_tool(def, handle_call_idc_func);
        }
    }
} // namespace ida_mcp::tools::exec_scripts
