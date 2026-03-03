#include "tools/tools.hpp"

#ifdef HAS_HEXRAYS
#include <hexrays.hpp>
#include <lines.hpp>
#endif

#include <fstream>
#include <sstream>
#include <cstdio>

namespace ida_mcp::tools::decompile_all {
    namespace {
        static json batch_decompile(const json &params) {
#ifdef HAS_HEXRAYS
            if (!init_hexrays_plugin())
                throw std::runtime_error("Hexrays decompiler not available");

            eavec_t funcaddrs;
            bool use_specific = false;

            if (params.contains("addresses") && params["addresses"].is_array()) {
                use_specific = true;
                for (const auto &addr_json: params["addresses"]) {
                    if (!addr_json.is_string())
                        continue;
                    auto ea = parse_ea(addr_json.get<std::string>());
                    if (ea.has_value())
                        funcaddrs.push_back(ea.value());
                }
                if (funcaddrs.empty())
                    throw std::runtime_error("No valid addresses provided");
            }

            int flags = VDRUN_SILENT | VDRUN_NEWFILE | VDRUN_MAYSTOP;

            char tmpname[QMAXPATH];
            qstring tmp_path;
            qtmpnam(tmpname, sizeof(tmpname));
            tmp_path = tmpname;
            tmp_path.append(".c");

            bool ok = decompile_many(
                tmp_path.c_str(),
                use_specific ? &funcaddrs : nullptr,
                flags);

            if (!ok) {
                qunlink(tmp_path.c_str());
                throw std::runtime_error("Batch decompilation failed or was cancelled");
            }

            std::ifstream infile(tmp_path.c_str());
            if (!infile.is_open()) {
                qunlink(tmp_path.c_str());
                throw std::runtime_error("Failed to read decompilation output");
            }

            std::ostringstream ss;
            ss << infile.rdbuf();
            infile.close();
            qunlink(tmp_path.c_str());

            std::string content = ss.str();

            size_t max_size = 4 * 1024 * 1024;
            if (params.contains("max_size") && params["max_size"].is_number_integer())
                max_size = params["max_size"].get<size_t>();

            bool truncated = false;
            if (content.size() > max_size) {
                content.resize(max_size);
                truncated = true;
            }

            json result;
            result["pseudocode"] = content;
            result["truncated"] = truncated;
            result["size_bytes"] = content.size();
            if (use_specific)
                result["function_count"] = funcaddrs.size();
            else
                result["function_count"] = get_func_qty();

            return result;
#else
            throw std::runtime_error("Hexrays support not compiled in");
#endif
        }
    } // anon namespace

    void register_tools(mcp::McpServer &server) {
        mcp::ToolDefinition def;
        def.name = "batch_decompile";
        def.description =
                "Batch decompile all functions (or a specific list) and return the pseudocode as a single block. "
                "Uses Hex-Rays decompile_many API. If no addresses given, decompiles all non-library functions.";
        def.input_schema = json{
            {"type", "object"},
            {
                "properties", {
                    {
                        "addresses", {
                            {"type", "array"},
                            {"items", {{"type", "string"}}},
                            {
                                "description",
                                "Optional list of hex addresses to decompile. If omitted, decompiles all non-lib functions."
                            }
                        }
                    },
                    {
                        "max_size", {
                            {"type", "integer"},
                            {"description", "Max output size in bytes (default 4MB). Output is truncated if exceeded."}
                        }
                    }
                }
            }
        };
        server.register_tool(def, batch_decompile);
    }
} // namespace ida_mcp::tools::decompile_all
