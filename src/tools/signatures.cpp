#include "tools/tools.hpp"
#include <funcs.hpp>

namespace ida_mcp::tools::signatures {
    namespace {
        json handle_list_signatures(const json &/*params*/) {
            int qty = get_idasgn_qty();
            json sigs = json::array();

            for (int i = 0; i < qty; i++) {
                qstring shortname, optlibs;
                int matched = get_idasgn_desc(&shortname, &optlibs, i);
                int state = calc_idasgn_state(i);

                qstring title;
                if (!shortname.empty())
                    get_idasgn_title(&title, shortname.c_str());

                json sig;
                sig["index"] = i;
                sig["short_name"] = shortname.c_str();
                sig["title"] = title.empty() ? json(nullptr) : json(title.c_str());
                sig["optional_libs"] = optlibs.empty() ? json(nullptr) : json(optlibs.c_str());
                sig["matched_count"] = matched;
                sig["state"] = state;

                const char *state_str;
                switch (state) {
                    case IDASGN_OK: state_str = "applied"; break;
                    case IDASGN_BADARG: state_str = "bad_argument"; break;
                    case IDASGN_APPLIED: state_str = "already_applied"; break;
                    case IDASGN_CURRENT: state_str = "current"; break;
                    case IDASGN_PLANNED: state_str = "planned"; break;
                    default: state_str = "unknown"; break;
                }
                sig["state_name"] = state_str;
                sigs.push_back(sig);
            }

            return json{
                {"signature_count", qty},
                {"signatures", sigs}
            };
        }

        json handle_apply_signature(const json &params) {
            std::string signame = params["name"].get<std::string>();

            int result = plan_to_apply_idasgn(signame.c_str());
            const char *result_str;
            switch (result) {
                case IDASGN_OK: result_str = "ok"; break;
                case IDASGN_BADARG: result_str = "signature_not_found"; break;
                case IDASGN_APPLIED: result_str = "already_applied"; break;
                case IDASGN_CURRENT: result_str = "already_current"; break;
                case IDASGN_PLANNED: result_str = "already_planned"; break;
                default: result_str = "error"; break;
            }

            return json{
                {"name", signame},
                {"result", result},
                {"result_name", result_str}
            };
        }
    }

    void register_tools(mcp::McpServer &server) {
        {
            mcp::ToolDefinition def;
            def.name = "list_signatures";
            def.description =
                "List all loaded FLIRT signatures and their application state. "
                "FLIRT signatures identify library functions (libc, STL, etc.) in stripped binaries.";
            def.input_schema = json{
                {"type", "object"},
                {"properties", json::object()}
            };
            server.register_tool(def, handle_list_signatures);
        }
        {
            mcp::ToolDefinition def;
            def.name = "apply_signature";
            def.description =
                "Apply a FLIRT signature file to the database. "
                "This identifies library functions matching the signature patterns.";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"name", {
                        {"type", "string"},
                        {"description", "Short name of the signature file (e.g. 'vc64rtf', 'gnulnx_x64')"}
                    }}
                }},
                {"required", json::array({"name"})}
            };
            server.register_tool(def, handle_apply_signature);
        }
    }
}
