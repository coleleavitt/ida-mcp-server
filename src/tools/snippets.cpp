#include "tools/tools.hpp"
#include <expr.hpp>

namespace ida_mcp::tools::snippets {
    namespace {
        json idc_value_to_json(const idc_value_t &v) {
            switch (v.vtype) {
                case VT_LONG:
                    return json{{"type", "long"}, {"value", static_cast<int64_t>(v.num)}};
                case VT_INT64:
                    return json{{"type", "int64"}, {"value", static_cast<int64_t>(v.i64)}};
                case VT_STR:
                    return json{{"type", "string"}, {"value", v.c_str()}};
                case VT_FLOAT: {
                    double fval = 0.0;
                    v.e.to_double(&fval);
                    return json{{"type", "float"}, {"value", fval}};
                }
                case VT_WILD:
                    return json{{"type", "void"}, {"value", nullptr}};
                default:
                    return json{{"type", "unknown"}, {"value", nullptr}};
            }
        }

        json compile_snippet_impl(const json &params) {
            std::string code = params["code"].get<std::string>();
            std::string func_name = "__mcp_snippet";
            if (params.contains("function_name") && !params["function_name"].is_null()) {
                func_name = params["function_name"].get<std::string>();
            }

            bool safe_only = false;
            if (params.contains("safe_only") && params["safe_only"].get<bool>()) {
                safe_only = true;
            }

            qstring errbuf;
            bool ok = ::compile_idc_snippet(func_name.c_str(), code.c_str(), &errbuf,
                                            nullptr, safe_only);

            if (!ok) {
                return json{
                    {"success", false},
                    {"error", errbuf.c_str()},
                    {"code", code}
                };
            }

            return json{
                {"success", true},
                {"function_name", func_name},
                {"code", code}
            };
        }

        json eval_snippet_impl(const json &params) {
            std::string code = params["code"].get<std::string>();

            idc_value_t result;
            qstring errbuf;
            bool ok = ::eval_idc_snippet(&result, code.c_str(), &errbuf);

            if (!ok) {
                return json{
                    {"success", false},
                    {"error", errbuf.c_str()},
                    {"code", code}
                };
            }

            return json{
                {"success", true},
                {"code", code},
                {"result", idc_value_to_json(result)}
            };
        }

        json call_idc_func_impl(const json &params) {
            std::string func_name = params["function_name"].get<std::string>();

            std::vector<idc_value_t> args;
            if (params.contains("args") && params["args"].is_array()) {
                for (const auto &arg: params["args"]) {
                    idc_value_t val;
                    if (arg.is_number_integer()) {
                        val.set_long(arg.get<sval_t>());
                    } else if (arg.is_string()) {
                        qstring s(arg.get<std::string>().c_str());
                        val.set_string(s);
                    } else if (arg.is_number_float()) {
                        val.set_long(static_cast<sval_t>(arg.get<double>()));
                    } else {
                        val.set_long(0);
                    }
                    args.push_back(val);
                }
            }

            idc_value_t result;
            qstring errbuf;
            bool ok = ::call_idc_func(&result, func_name.c_str(),
                                      args.empty() ? nullptr : args.data(),
                                      args.size(), &errbuf);

            if (!ok) {
                return json{
                    {"success", false},
                    {"error", errbuf.c_str()},
                    {"function_name", func_name}
                };
            }

            return json{
                {"success", true},
                {"function_name", func_name},
                {"result", idc_value_to_json(result)}
            };
        }
    }

    void register_tools(mcp::McpServer &server) { {
            mcp::ToolDefinition def;
            def.name = "compile_idc_snippet";
            def.description = "Compile IDC code into a callable function. "
                    "Supports multi-statement code blocks, variable declarations, loops, etc. "
                    "Call call_idc_function afterwards to execute it.";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {"code", {{"type", "string"}, {"description", "IDC code to compile"}}},
                        {
                            "function_name",
                            {
                                {"type", "string"},
                                {"description", "Name for the compiled function (default: __mcp_snippet)"}
                            }
                        },
                        {
                            "safe_only",
                            {{"type", "boolean"}, {"description", "Only allow safe function calls (default false)"}}
                        }
                    }
                },
                {"required", json::array({"code"})}
            };
            server.register_tool(def, compile_snippet_impl);
        } {
            mcp::ToolDefinition def;
            def.name = "eval_idc_snippet";
            def.description = "Compile and execute IDC statements. "
                    "Unlike eval_expression, this handles multi-statement code with variable declarations, "
                    "loops, conditionals, and function calls. Returns the result of the last expression.";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {"code", {{"type", "string"}, {"description", "IDC statements to execute"}}}
                    }
                },
                {"required", json::array({"code"})}
            };
            server.register_tool(def, eval_snippet_impl);
        } {
            mcp::ToolDefinition def;
            def.name = "call_idc_function";
            def.description = "Call a previously compiled or built-in IDC function by name. "
                    "Supports passing integer, string, and float arguments.";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {"function_name", {{"type", "string"}, {"description", "IDC function name"}}},
                        {
                            "args", {
                                {"type", "array"}, {"description", "Arguments to pass (integers, strings, or floats)"},
                                {"items", {}}
                            }
                        }
                    }
                },
                {"required", json::array({"function_name"})}
            };
            server.register_tool(def, call_idc_func_impl);
        }
    }
}
