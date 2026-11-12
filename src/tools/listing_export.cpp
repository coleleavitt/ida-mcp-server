// Headless listing export of IDA 9.5: disassembly ranges, functions and
// pseudocode rendered as plain text or inline-styled HTML. lines.hpp:839-1095.

#include "tools/tools.hpp"
#include <kernwin.hpp>
#include <lines.hpp>
#include <memory>

#ifdef HAS_HEXRAYS
#include <hexrays.hpp>
#endif

namespace ida_mcp::tools::listing_export {
    namespace {
        ea_t require_ea(const json &params, const char *key) {
            if (!params[key].is_string())
                throw std::runtime_error(std::string(key) + " must be a hex address string");
            auto ea = parse_ea(params[key].get<std::string>());
            if (!ea)
                throw std::runtime_error(std::string("Invalid address in ") + key);
            return *ea;
        }

        int64 positive_param(const json &params, const char *key, int64 fallback, int64 min) {
            if (!params.contains(key))
                return fallback;
            if (!params[key].is_number_integer() || params[key].get<int64>() < min)
                throw std::runtime_error(std::string(key) + " must be an integer >= " + std::to_string(min));
            return params[key].get<int64>();
        }
    }

    static json export_listing(const json &params) {
        const bool has_function = params.contains("function");
        const bool has_start = params.contains("start");
        if (has_function == has_start)
            throw std::runtime_error("Pass either function or start (with optional end)");

        const std::string format = params.value("format", "plain");
        uint32 flags;
        if (format == "plain")
            flags = LLFMT_PLAIN;
        else if (format == "html")
            flags = LLFMT_HTML_INLINE;
        else
            throw std::runtime_error("format must be plain or html");

        const bool pseudocode = params.value("pseudocode", false);
        const int64 max_bytes = positive_param(params, "max_bytes", 65536, 1);
        const int64 skip_lines = positive_param(params, "skip_lines", 0, 0);

        export_listing_t cfg;
        json scope;
        if (has_function) {
            const ea_t func_ea = get_func_start(require_ea(params, "function"));
            if (func_ea == BADADDR)
                throw std::runtime_error("Address is not in a function");
            if (!cfg.add_function(func_ea))
                throw std::runtime_error("No function at " + format_ea(func_ea));
            qstring name;
            get_func_name(&name, func_ea);
            scope = json{{"function", format_ea(func_ea)}, {"name", name.c_str()}};
            if (pseudocode) {
#ifdef HAS_HEXRAYS
                if (!init_hexrays_plugin())
                    throw std::runtime_error("Hexrays decompiler not available (check license)");
                hexrays_failure_t hf;
                cfuncptr_t cfunc = decompile_function(func_ea, &hf, DECOMP_NO_WAIT);
                if (cfunc == nullptr) {
                    qstring err = hf.desc();
                    if (hf.code == MERR_TIMEOUT)
                        err.sprnt("timed out after %d ms (MERR_TIMEOUT)", get_decompiler_timeout());
                    throw std::runtime_error(std::string("Decompilation failed: ") + err.c_str());
                }
                if (!cfg.add_pseudocode(&cfunc->get_pseudocode(), func_ea))
                    throw std::runtime_error("The listing exporter could not add the pseudocode");
#else
                throw std::runtime_error("Hexrays support not compiled in");
#endif
            }
        } else {
            if (pseudocode)
                throw std::runtime_error("pseudocode requires function");
            const ea_t start = require_ea(params, "start");
            const ea_t end = params.contains("end") ? require_ea(params, "end") : BADADDR;
            if (end != BADADDR && end <= start)
                throw std::runtime_error("end must be greater than start");
            cfg.add_disasm_range(start, end);
            scope = json{{"start", format_ea(start)}, {"end", end == BADADDR ? json(nullptr) : json(format_ea(end))}};
        }

        // Stream the lines and stop at the byte bound, so a large range is
        // never rendered in full just to be cut.
        std::string text;
        int64 line_no = 0;
        int64 emitted = 0;
        bool truncated = false;
        for (size_t r = 0; r < cfg.ranges.size() && !truncated; ++r) {
            std::unique_ptr<listing_lines_t> gen(cfg.create_lines(flags, r));
            if (!gen)
                throw std::runtime_error("The listing exporter returned no generator for range " + std::to_string(r));
            for (const listing_line_t *line = gen->next(); line != nullptr; line = gen->next(), ++line_no) {
                if (line_no < skip_lines)
                    continue;
                const size_t need = line->text.length() + (text.empty() ? 0 : 1);
                if (static_cast<int64>(text.size() + need) > max_bytes) {
                    truncated = true;
                    break;
                }
                if (!text.empty())
                    text += '\n';
                text.append(line->text.c_str(), line->text.length());
                ++emitted;
            }
        }

        json result = scope;
        result["format"] = format;
        result["pseudocode"] = pseudocode;
        result["skip_lines"] = skip_lines;
        result["lines"] = emitted;
        result["bytes"] = text.size();
        result["truncated"] = truncated;
        result["next_skip_lines"] = truncated ? json(skip_lines + emitted) : json(nullptr);
        result["text"] = std::move(text);
        return result;
    }

    void register_tools(mcp::McpServer &server) {
        mcp::ToolDefinition def;
        def.name = "export_listing";
        def.description = "Export the IDA listing of a function (optionally followed by its pseudocode) "
                "or of an address range, as plain text or inline-styled HTML lines, up to max_bytes. "
                "When truncated, call again with skip_lines = next_skip_lines.";
        def.input_schema = json{
            {"type", "object"},
            {"properties", {
                {"function", {{"type", "string"}, {"description", "Hex address inside the function (tail chunks included)"}}},
                {"start", {{"type", "string"}, {"description", "Hex start of a disassembly range"}}},
                {"end", {{"type", "string"}, {"description", "Hex end of the range (exclusive); omitted = to the end of the listing"}}},
                {"pseudocode", {{"type", "boolean"}, {"default", false}, {"description", "function: append the Hex-Rays pseudocode"}}},
                {"format", {{"type", "string"}, {"enum", json::array({"plain", "html"})}, {"default", "plain"}}},
                {"max_bytes", {{"type", "integer"}, {"minimum", 1}, {"default", 65536}, {"description", "Bound on the returned text"}}},
                {"skip_lines", {{"type", "integer"}, {"minimum", 0}, {"default", 0}, {"description", "Lines to skip before output starts"}}}
            }}
        };
        server.register_tool(def, export_listing);
    }
} // namespace ida_mcp::tools::listing_export
