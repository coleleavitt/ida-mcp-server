#include "tools/tools.hpp"
#include <nalt.hpp>

namespace ida_mcp::tools::imports {
    namespace {
        // Callback for enum_import_names()
        struct import_collector_t {
            json *imports_array;
            const char *module_name;
            size_t *count;
            size_t limit;
        };

        static int idaapi import_enum_cb(ea_t ea, const char *name, uval_t ord, void *param) {
            auto *ctx = static_cast<import_collector_t *>(param);

            if (*(ctx->count) >= ctx->limit) {
                return 0; // Stop enumeration
            }

            json import_obj;
            import_obj["module"] = ctx->module_name;
            import_obj["name"] = name ? name : "";
            import_obj["address"] = format_ea(ea);
            import_obj["ordinal"] = static_cast<uint64_t>(ord);

            ctx->imports_array->push_back(import_obj);
            (*(ctx->count))++;

            return 1; // Continue enumeration
        }

        json handle_list_imports(const json &params) {
            size_t limit = params.value("limit", 1000);

            uint module_count = get_import_module_qty();

            if (module_count == 0) {
                return json{
                    {"module_count", 0},
                    {"import_count", 0},
                    {"imports", json::array()},
                    {"note", "No import modules found in this binary."}
                };
            }

            json imports = json::array();
            size_t total_count = 0;

            for (uint mod_idx = 0; mod_idx < module_count && total_count < limit; mod_idx++) {
                qstring module_name;
                if (!get_import_module_name(&module_name, mod_idx)) {
                    continue;
                }

                import_collector_t ctx;
                ctx.imports_array = &imports;
                ctx.module_name = module_name.c_str();
                ctx.count = &total_count;
                ctx.limit = limit;

                enum_import_names(mod_idx, import_enum_cb, &ctx);
            }

            return json{
                {"module_count", module_count},
                {"import_count", imports.size()},
                {"truncated", imports.size() >= limit},
                {"imports", imports}
            };
        }
    } // anonymous namespace

    void register_tools(mcp::McpServer &server) {
        mcp::ToolDefinition def;
        def.name = "list_imports";
        def.description = "List imported functions";
        def.input_schema = json{
            {"type", "object"},
            {
                "properties", {
                    {
                        "limit", {
                            {"type", "number"},
                            {"description", "Max results"},
                            {"default", 1000}
                        }
                    }
                }
            }
        };

        server.register_tool(def, handle_list_imports);
    }
} // namespace ida_mcp::tools::imports
