#include "tools/tools.hpp"
#include <entry.hpp>

namespace ida_mcp::tools::exports {
    namespace {
        json handle_list_exports(const json &params) {
            size_t limit = params.value("limit", 1000);

            size_t export_count = get_entry_qty();

            if (export_count == 0) {
                return json{
                    {"export_count", 0},
                    {"exports", json::array()},
                    {"note", "No exports/entry points found in this binary."}
                };
            }

            json exports = json::array();
            size_t actual_count = std::min(export_count, limit);

            for (size_t idx = 0; idx < actual_count; idx++) {
                uval_t ordinal = get_entry_ordinal(idx);
                ea_t addr = get_entry(ordinal);

                qstring name;
                get_entry_name(&name, ordinal);

                json export_obj;
                export_obj["name"] = name.empty() ? nullptr : json(name.c_str());
                export_obj["address"] = format_ea(addr);
                export_obj["ordinal"] = static_cast<uint64_t>(ordinal);

                exports.push_back(export_obj);
            }

            return json{
                {"export_count", export_count},
                {"returned", actual_count},
                {"truncated", export_count > limit},
                {"exports", exports}
            };
        }
    } // anonymous namespace

    void register_tools(mcp::McpServer &server) {
        mcp::ToolDefinition def;
        def.name = "list_exports";
        def.description = "List exported functions";
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

        server.register_tool(def, handle_list_exports);
    }
} // namespace ida_mcp::tools::exports
