#include "tools/tools.hpp"
#include <funcs.hpp>
#include <kernwin.hpp>

// 9.3-only APIs — zero-arg functions that operate on the current function
// (internally call get_func(screen_ea())).
// We use jumpto() to set screen_ea before calling them.
extern "C" {
bool backup_metadata(void);

bool has_backup_metadata(void);

bool revert_metadata(void);
}

namespace ida_mcp::tools::metadata_backup {
    namespace {
        json backup_metadata_impl(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            func_t *func = get_func(ea);
            if (func == nullptr) {
                throw std::runtime_error("Address " + format_ea(ea) + " is not within a function");
            }

            jumpto(ea);

            bool result = ::backup_metadata();

            qstring name;
            std::string name_str;
            if (get_func_name(&name, func->start_ea) > 0) {
                name_str = name.c_str();
            } else {
                name_str = format_ea(func->start_ea);
            }

            return json{
                {"address", format_ea(ea)},
                {"function", name_str},
                {"function_start", format_ea(func->start_ea)},
                {"success", result}
            };
        }

        json has_backup_metadata_impl(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            func_t *func = get_func(ea);
            if (func == nullptr) {
                throw std::runtime_error("Address " + format_ea(ea) + " is not within a function");
            }

            jumpto(ea);

            bool has_backup = ::has_backup_metadata();

            qstring name;
            std::string name_str;
            if (get_func_name(&name, func->start_ea) > 0) {
                name_str = name.c_str();
            } else {
                name_str = format_ea(func->start_ea);
            }

            return json{
                {"address", format_ea(ea)},
                {"function", name_str},
                {"function_start", format_ea(func->start_ea)},
                {"has_backup", has_backup}
            };
        }

        json revert_metadata_impl(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            func_t *func = get_func(ea);
            if (func == nullptr) {
                throw std::runtime_error("Address " + format_ea(ea) + " is not within a function");
            }

            jumpto(ea);

            bool result = ::revert_metadata();

            qstring name;
            std::string name_str;
            if (get_func_name(&name, func->start_ea) > 0) {
                name_str = name.c_str();
            } else {
                name_str = format_ea(func->start_ea);
            }

            return json{
                {"address", format_ea(ea)},
                {"function", name_str},
                {"function_start", format_ea(func->start_ea)},
                {"success", result}
            };
        }
    }

    void register_tools(mcp::McpServer &server) { {
            mcp::ToolDefinition def;
            def.name = "backup_metadata";
            def.description = "Backup the metadata (types, names, comments, etc.) of the function "
                    "containing the given address. Creates a snapshot that can later be restored "
                    "with revert_metadata. IDA 9.3+ only.";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {"address", {{"type", "string"}, {"description", "Hex address within the target function"}}}
                    }
                },
                {"required", json::array({"address"})}
            };
            server.register_tool(def, backup_metadata_impl);
        } {
            mcp::ToolDefinition def;
            def.name = "has_backup_metadata";
            def.description = "Check whether a metadata backup exists for the function containing "
                    "the given address. IDA 9.3+ only.";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {"address", {{"type", "string"}, {"description", "Hex address within the target function"}}}
                    }
                },
                {"required", json::array({"address"})}
            };
            server.register_tool(def, has_backup_metadata_impl);
        } {
            mcp::ToolDefinition def;
            def.name = "revert_metadata";
            def.description = "Revert the function containing the given address to its previously "
                    "backed-up metadata state. Restores types, names, comments, etc. "
                    "Must have a backup (see has_backup_metadata). IDA 9.3+ only.";
            def.input_schema = json{
                {"type", "object"},
                {
                    "properties", {
                        {"address", {{"type", "string"}, {"description", "Hex address within the target function"}}}
                    }
                },
                {"required", json::array({"address"})}
            };
            server.register_tool(def, revert_metadata_impl);
        }
    }
}
