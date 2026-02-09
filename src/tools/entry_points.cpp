#include "tools/tools.hpp"
#include <entry.hpp>

namespace ida_mcp::tools::entry_points {
    namespace {
        json handle_get_entry_points(const json &params) {
            size_t entry_count = get_entry_qty();

            if (entry_count == 0) {
                return json{
                    {"entry_count", 0},
                    {"entry_points", json::array()},
                    {"note", "No entry points/exports found in this binary."}
                };
            }

            json entry_points = json::array();

            for (size_t idx = 0; idx < entry_count; idx++) {
                uval_t ordinal = get_entry_ordinal(idx);
                ea_t addr = get_entry(ordinal);

                qstring name;
                get_entry_name(&name, ordinal);

                json entry_obj;
                entry_obj["name"] = name.empty() ? nullptr : json(name.c_str());
                entry_obj["address"] = format_ea(addr);
                entry_obj["ordinal"] = static_cast<uint64_t>(ordinal);

                entry_points.push_back(entry_obj);
            }

            return json{
                {"entry_count", entry_count},
                {"entry_points", entry_points}
            };
        }
    } // anonymous namespace

    void register_tools(mcp::McpServer &server) {
        mcp::ToolDefinition def;
        def.name = "get_entry_points";
        def.description = "Get all entry points";
        def.input_schema = json{
            {"type", "object"},
            {"properties", json::object()}
        };

        server.register_tool(def, handle_get_entry_points);
    }
} // namespace ida_mcp::tools::entry_points
