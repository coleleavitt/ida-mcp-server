#include "tools/tools.hpp"
#include <undo.hpp>

namespace ida_mcp::tools::undo {
    namespace {
        json create_undo_point_impl(const json &params) {
            bool success = ::create_undo_point(nullptr, 0);

            return json{
                {"success", success}
            };
        }

        json perform_undo_impl(const json &params) {
            bool success = ::perform_undo();

            return json{
                {"success", success}
            };
        }

        json perform_redo_impl(const json &params) {
            bool success = ::perform_redo();

            return json{
                {"success", success}
            };
        }

        json get_undo_label_impl(const json &params) {
            qstring undo_label;
            bool has_undo = get_undo_action_label(&undo_label);

            qstring redo_label;
            bool has_redo = get_redo_action_label(&redo_label);

            return json{
                {"has_undo", has_undo},
                {"undo_label", has_undo ? undo_label.c_str() : ""},
                {"has_redo", has_redo},
                {"redo_label", has_redo ? redo_label.c_str() : ""}
            };
        }
    }

    void register_tools(mcp::McpServer &server) { {
            mcp::ToolDefinition def;
            def.name = "create_undo_point";
            def.description = "Create an undo checkpoint before making changes";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {}},
                {"required", json::array()}
            };
            server.register_tool(def, create_undo_point_impl);
        } {
            mcp::ToolDefinition def;
            def.name = "perform_undo";
            def.description = "Undo the last operation";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {}},
                {"required", json::array()}
            };
            server.register_tool(def, perform_undo_impl);
        } {
            mcp::ToolDefinition def;
            def.name = "perform_redo";
            def.description = "Redo the last undone operation";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {}},
                {"required", json::array()}
            };
            server.register_tool(def, perform_redo_impl);
        } {
            mcp::ToolDefinition def;
            def.name = "get_undo_label";
            def.description = "Get labels for available undo/redo actions";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {}},
                {"required", json::array()}
            };
            server.register_tool(def, get_undo_label_impl);
        }
    }
}
