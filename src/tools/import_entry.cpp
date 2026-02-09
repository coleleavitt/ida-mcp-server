#include "tools/tools.hpp"
#include <nalt.hpp>

struct import_info_t
{
    qstring name;
    qvector<uval_t> ordinals;
    int mod_index;
};

extern "C" bool get_import_entry(import_info_t *out, size_t idx);

namespace ida_mcp::tools::import_entry {
    namespace {

        json handle_get_import_entry(const json &params) {
            if (!params.contains("index")) {
                return json{{"error", "Missing required parameter: index"}};
            }

            size_t idx = params["index"].get<size_t>();

            import_info_t info;
            bool ok = get_import_entry(&info, idx);

            if (!ok) {
                return json{
                    {"success", false},
                    {"error", "Import entry not found at index " + std::to_string(idx)},
                    {"note", "PE-only API. Use list_imports for non-PE binaries."}
                };
            }

            qstring mod_name;
            get_import_module_name(&mod_name, info.mod_index);

            json ordinals_arr = json::array();
            for (size_t i = 0; i < info.ordinals.size(); i++) {
                ordinals_arr.push_back(static_cast<uint64_t>(info.ordinals[i]));
            }

            return json{
                {"success", true},
                {"index", idx},
                {"name", info.name.empty() ? "" : info.name.c_str()},
                {"ordinals", ordinals_arr},
                {"mod_index", info.mod_index},
                {"module_name", mod_name.empty() ? "" : mod_name.c_str()}
            };
        }

        json handle_get_import_entries_range(const json &params) {
            size_t start = params.value("start", static_cast<size_t>(0));
            size_t count = params.value("count", static_cast<size_t>(100));
            size_t max_count = 10000;
            if (count > max_count) count = max_count;

            json entries = json::array();
            size_t found = 0;
            size_t consecutive_misses = 0;

            for (size_t idx = start; found < count; idx++) {
                import_info_t info;
                bool ok = get_import_entry(&info, idx);

                if (!ok) {
                    consecutive_misses++;
                    if (consecutive_misses > 100) break;
                    continue;
                }
                consecutive_misses = 0;

                qstring mod_name;
                get_import_module_name(&mod_name, info.mod_index);

                json ordinals_arr = json::array();
                for (size_t i = 0; i < info.ordinals.size(); i++) {
                    ordinals_arr.push_back(static_cast<uint64_t>(info.ordinals[i]));
                }

                entries.push_back(json{
                    {"index", idx},
                    {"name", info.name.empty() ? "" : info.name.c_str()},
                    {"ordinals", ordinals_arr},
                    {"mod_index", info.mod_index},
                    {"module_name", mod_name.empty() ? "" : mod_name.c_str()}
                });
                found++;
            }

            return json{
                {"success", true},
                {"start", start},
                {"requested", count},
                {"returned", entries.size()},
                {"entries", entries},
                {"note", "PE-only API (IDA 9.3+)"}
            };
        }

    } // anonymous namespace

    void register_tools(mcp::McpServer &server) {
        {
            mcp::ToolDefinition def;
            def.name = "get_import_entry";
            def.description = "Get a single import entry by index (PE-only, IDA 9.3+). "
                              "Returns import name, ordinals, and module info.";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"index", {
                        {"type", "number"},
                        {"description", "Import entry index"}
                    }}
                }},
                {"required", json::array({"index"})}
            };
            server.register_tool(def, handle_get_import_entry);
        }

        {
            mcp::ToolDefinition def;
            def.name = "get_import_entries";
            def.description = "Get a range of import entries (PE-only, IDA 9.3+). "
                              "Enumerates import entries starting from a given index.";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"start", {
                        {"type", "number"},
                        {"description", "Starting index (default: 0)"},
                        {"default", 0}
                    }},
                    {"count", {
                        {"type", "number"},
                        {"description", "Max entries to return (default: 100, max: 10000)"},
                        {"default", 100}
                    }}
                }}
            };
            server.register_tool(def, handle_get_import_entries_range);
        }
    }
} // namespace ida_mcp::tools::import_entry
