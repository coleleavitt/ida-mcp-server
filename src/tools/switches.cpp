#include "tools/tools.hpp"
#include <nalt.hpp>
#include <xref.hpp>
#include <funcs.hpp>

namespace ida_mcp::tools::switches {
    namespace {
        json handle_get_switch_info(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            switch_info_t si;
            ssize_t result = get_switch_info(&si, ea);

            if (result <= 0) {
                throw std::runtime_error(
                    "No switch/jump table found at address " + format_ea(ea) + ". "
                    "This address may not be an indirect jump instruction, or IDA has not "
                    "detected the switch pattern yet. Try running auto-analysis or manually "
                    "creating the switch table in IDA."
                );
            }

            // Get case values and targets
            casevec_t cases;
            eavec_t targets;
            if (!calc_switch_cases(&cases, &targets, ea, si)) {
                throw std::runtime_error("Failed to calculate switch cases at " + format_ea(ea));
            }

            // Get function name if inside a function
            func_t *func = get_func(ea);
            std::string func_name;
            if (func != nullptr) {
                func_name = get_function_name(func);
            }

            // Build cases array - casevec_t is vector of vectors
            json cases_json = json::array();
            for (size_t i = 0; i < cases.size() && i < targets.size(); i++) {
                const svalvec_t &case_values = cases[i];

                // Each case can have multiple values, but typically just one
                for (size_t j = 0; j < case_values.size(); j++) {
                    json case_obj;
                    case_obj["value"] = static_cast<int64_t>(case_values[j]);
                    case_obj["target"] = format_ea(targets[i]);

                    // Try to get function name for target
                    func_t *target_func = get_func(targets[i]);
                    if (target_func != nullptr) {
                        case_obj["function_name"] = get_function_name(target_func);
                    }

                    cases_json.push_back(case_obj);
                }
            }

            return json{
                {"address", format_ea(ea)},
                {"function_name", func_name.empty() ? nullptr : json(func_name)},
                {"jump_table", format_ea(si.jumps)},
                {"case_count", cases.size()},
                {"default_target", si.defjump == BADADDR ? nullptr : json(format_ea(si.defjump))},
                {"lowcase", static_cast<int64_t>(si.lowcase)},
                {"ncases", static_cast<uint64_t>(si.ncases)},
                {"is_sparse", (si.flags & SWI_SPARSE) != 0},
                {"cases", cases_json}
            };
        }

        json handle_enumerate_switch_cases(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            switch_info_t si;
            ssize_t result = get_switch_info(&si, ea);

            if (result <= 0) {
                throw std::runtime_error("No switch/jump table found at address " + format_ea(ea));
            }

            // Get case values and targets
            casevec_t cases;
            eavec_t targets;
            if (!calc_switch_cases(&cases, &targets, ea, si)) {
                throw std::runtime_error("Failed to calculate switch cases at " + format_ea(ea));
            }

            // Build enhanced cases array with function names
            json cases_json = json::array();
            for (size_t i = 0; i < cases.size() && i < targets.size(); i++) {
                const svalvec_t &case_values = cases[i];

                for (size_t j = 0; j < case_values.size(); j++) {
                    json case_obj;
                    case_obj["value"] = static_cast<int64_t>(case_values[j]);
                    case_obj["target"] = format_ea(targets[i]);

                    // Get function name for target
                    func_t *target_func = get_func(targets[i]);
                    if (target_func != nullptr) {
                        case_obj["function_name"] = get_function_name(target_func);
                    }

                    cases_json.push_back(case_obj);
                }
            }

            json result_obj;
            result_obj["address"] = format_ea(ea);
            result_obj["jump_table"] = format_ea(si.jumps);
            result_obj["case_count"] = cases.size();
            result_obj["cases"] = cases_json;

            // Add default case if it exists
            if (si.defjump != BADADDR) {
                result_obj["default_target"] = format_ea(si.defjump);

                func_t *default_func = get_func(si.defjump);
                if (default_func != nullptr) {
                    result_obj["default_function_name"] = get_function_name(default_func);
                }
            }

            return result_obj;
        }

        json handle_find_switches_in_function(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            func_t *func = get_func(ea);
            if (func == nullptr) {
                throw std::runtime_error("No function found at address " + format_ea(ea));
            }

            std::string func_name = get_function_name(func);

            // Scan function for switches
            json switches = json::array();
            for (ea_t addr = func->start_ea; addr < func->end_ea;) {
                switch_info_t si;
                if (get_switch_info(&si, addr) > 0) {
                    json switch_obj;
                    switch_obj["address"] = format_ea(addr);
                    switch_obj["jump_table"] = format_ea(si.jumps);
                    switch_obj["case_count"] = static_cast<uint64_t>(si.ncases);

                    switches.push_back(switch_obj);
                }

                addr = next_head(addr, func->end_ea);
                if (addr == BADADDR) {
                    break;
                }
            }

            return json{
                {"function_address", format_ea(func->start_ea)},
                {"function_name", func_name},
                {"switch_count", switches.size()},
                {"switches", switches}
            };
        }
    } // anonymous namespace

    void register_tools(mcp::McpServer &server) {
        // get_switch_info
        {
            mcp::ToolDefinition def;
            def.name = "get_switch_info";
            def.description = "Analyze switch/jump table";
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
            server.register_tool(def, handle_get_switch_info);
        }

        // enumerate_switch_cases
        {
            mcp::ToolDefinition def;
            def.name = "enumerate_switch_cases";
            def.description = "Enumerate switch case values";
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
            server.register_tool(def, handle_enumerate_switch_cases);
        }

        // find_switches_in_function
        {
            mcp::ToolDefinition def;
            def.name = "find_switches_in_function";
            def.description = "Find switches in function";
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
            server.register_tool(def, handle_find_switches_in_function);
        }
    }
} // namespace ida_mcp::tools::switches
