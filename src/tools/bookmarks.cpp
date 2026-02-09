#include "tools/tools.hpp"
#include <moves.hpp>
#include <kernwin.hpp>

namespace ida_mcp::tools::bookmarks {
    namespace {
        json list_bookmarks_impl(const json &params) {
            json results = json::array();

            idaplace_t dummy_place(inf_get_min_ea(), 0);
            renderer_info_t rinfo;
            lochist_entry_t dummy_entry(&dummy_place, rinfo);

            uint32 count = bookmarks_t_size(dummy_entry, nullptr);

            for (uint32 i = 0; i < count; i++) {
                idaplace_t place(0, 0);
                renderer_info_t ri;
                lochist_entry_t entry(&place, ri);
                qstring desc;
                uint32 idx = i;

                if (bookmarks_t_get(&entry, &desc, &idx, nullptr)) {
                    const place_t *p = entry.place();
                    ea_t ea = (p != nullptr) ? p->toea() : BADADDR;

                    results.push_back(json{
                        {"index", idx},
                        {"address", format_ea(ea)},
                        {"description", desc.empty() ? "" : desc.c_str()}
                    });
                }
            }

            return json{
                {"count", count},
                {"bookmarks", results}
            };
        }

        json set_bookmark_impl(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt.has_value()) {
                throw std::runtime_error("Invalid address format");
            }
            ea_t ea = ea_opt.value();

            std::string description = params.value("description", "");
            uint32 slot = params.value("index", static_cast<int>(BOOKMARKS_BAD_INDEX));

            idaplace_t place(ea, 0);
            renderer_info_t rinfo;
            lochist_entry_t entry(&place, rinfo);

            uint32 index = bookmarks_t_mark(
                entry,
                slot,
                nullptr,
                description.empty() ? nullptr : description.c_str(),
                nullptr);

            bool success = (index != BOOKMARKS_BAD_INDEX);

            return json{
                {"address", format_ea(ea)},
                {"description", description},
                {"index", index},
                {"success", success}
            };
        }

        json delete_bookmark_impl(const json &params) {
            uint32 index = params["index"].get<uint32>();

            idaplace_t dummy_place(inf_get_min_ea(), 0);
            renderer_info_t rinfo;
            lochist_entry_t dummy_entry(&dummy_place, rinfo);

            bool success = bookmarks_t_erase(dummy_entry, index, nullptr);

            return json{
                {"index", index},
                {"success", success}
            };
        }
    }

    void register_tools(mcp::McpServer &server) {
        {
            mcp::ToolDefinition def;
            def.name = "list_bookmarks";
            def.description = "List all bookmarks in the database";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {}},
                {"required", json::array()}
            };
            server.register_tool(def, list_bookmarks_impl);
        }

        {
            mcp::ToolDefinition def;
            def.name = "set_bookmark";
            def.description = "Create a bookmark at address";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Hex address"}}},
                    {"description", {{"type", "string"}, {"description", "Bookmark description"}}},
                    {"index", {{"type", "integer"}, {"description", "Slot number (optional, auto-assigned if omitted)"}}}
                }},
                {"required", json::array({"address"})}
            };
            server.register_tool(def, set_bookmark_impl);
        }

        {
            mcp::ToolDefinition def;
            def.name = "delete_bookmark";
            def.description = "Delete a bookmark by index";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"index", {{"type", "integer"}, {"description", "Bookmark index"}}}
                }},
                {"required", json::array({"index"})}
            };
            server.register_tool(def, delete_bookmark_impl);
        }
    }
}
