#include "tools/tools.hpp"
#include <auto.hpp>

namespace ida_mcp::tools::auto_analysis {
    namespace {
        const char *auto_state_to_name(atype_t state) {
            switch (state) {
                case AU_NONE: return "AU_NONE (idle)";
                case AU_CODE: return "AU_CODE (making code)";
                case AU_PROC: return "AU_PROC (making procedures)";
                case AU_USED: return "AU_USED (reanalyzing)";
                case AU_FINAL: return "AU_FINAL (final pass)";
                default: return "Unknown";
            }
        }

        json handle_is_auto_analysis_complete(const json &params) {
            atype_t state = get_auto_state();
            bool is_complete = (state == AU_NONE);

            const char *state_name = auto_state_to_name(state);
            const char *note = is_complete
                                   ? "Auto-analysis is complete. Database is ready for queries."
                                   : "Auto-analysis is still running. Results may be incomplete. Wait for completion before performing comprehensive analysis.";

            return json{
                {"is_complete", is_complete},
                {"state_value", static_cast<int>(state)},
                {"state_name", state_name},
                {"ready_for_analysis", is_complete},
                {"note", note}
            };
        }
    } // anonymous namespace

    void register_tools(mcp::McpServer &server) {
        mcp::ToolDefinition def;
        def.name = "is_auto_analysis_complete";
        def.description = "Check if auto analysis complete";
        def.input_schema = json{
            {"type", "object"},
            {"properties", json::object()}
        };

        server.register_tool(def, handle_is_auto_analysis_complete);
    }
} // namespace ida_mcp::tools::auto_analysis
