#include "tools/tools.hpp"
#include <nalt.hpp>

namespace ida_mcp::tools::import_entry {
    namespace {
        json handle_get_import_entry(const json &params) {
            if (!params.contains("address") || !params["address"].is_string())
                throw std::runtime_error("Missing required parameter: address");
            auto ea = parse_ea(params["address"].get<std::string>());
            if (!ea)
                throw std::runtime_error("Invalid address");

            import_entry_t entry;
            if (!get_import_entry(&entry, *ea)) {
                return json{
                    {"success", false},
                    {"error", "No import entry at " + format_ea(*ea)}
                };
            }

            qstring mod_name;
            get_import_module_name(&mod_name, entry.mod_index);

            json ordinals = json::array();
            for (uval_t ord: entry.ordinals)
                ordinals.push_back(static_cast<uint64_t>(ord));

            return json{
                {"success", true},
                {"address", format_ea(*ea)},
                {"name", entry.name.c_str()},
                {"ordinals", ordinals},
                {"mod_index", entry.mod_index},
                {"module_name", mod_name.c_str()}
            };
        }
    } // anonymous namespace

    void register_tools(mcp::McpServer &server) {
        mcp::ToolDefinition def;
        def.name = "get_import_entry";
        def.description = "Get the import entry (name, ordinals, module) at an import address";
        def.input_schema = json{
            {"type", "object"},
            {"properties", {{"address", {{"type", "string"}, {"description", "Hex address of the import"}}}}},
            {"required", json::array({"address"})}
        };
        server.register_tool(def, handle_get_import_entry);
    }
} // namespace ida_mcp::tools::import_entry
