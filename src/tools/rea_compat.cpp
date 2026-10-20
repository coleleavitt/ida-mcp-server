// Read-only tool profile matching mrexodia/ida-pro-mcp 1.4.0 ("legacy"), which is
// the attached-GUI contract REA's IDA provider speaks. Served on /rea/mcp so the
// main /mcp tool surface keeps its own argument and result shapes.
// Contract: rea/src/ida/IdaProtocolValues.ts and IdaOperationRunner.ts.

#include "tools/tools.hpp"
#include <nalt.hpp>
#include <set>

namespace ida_mcp::tools::rea_compat {
    namespace {
        // nlohmann::json throws when dumping invalid UTF-8, and string literals
        // and disassembly can contain arbitrary bytes.
        std::string utf8_clean(const std::string &in) {
            std::string out;
            out.reserve(in.size());
            size_t i = 0;
            while (i < in.size()) {
                auto c = static_cast<unsigned char>(in[i]);
                size_t len = c < 0x80 ? 1 : (c >> 5) == 0x6 ? 2 : (c >> 4) == 0xE ? 3 : (c >> 3) == 0x1E ? 4 : 0;
                bool valid = len != 0 && i + len <= in.size();
                for (size_t k = 1; valid && k < len; ++k)
                    valid = (static_cast<unsigned char>(in[i + k]) & 0xC0) == 0x80;
                if (valid) {
                    out.append(in, i, len);
                    i += len;
                } else {
                    out += "\xEF\xBF\xBD";
                    ++i;
                }
            }
            return out;
        }

        std::string hex(uint64 value) {
            char buf[32];
            qsnprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(value));
            return buf;
        }

        ea_t require_ea(const json &params, const char *key) {
            if (!params.contains(key) || !params[key].is_string())
                throw std::runtime_error(std::string("Missing required parameter: ") + key);
            auto ea = parse_ea(params[key].get<std::string>());
            if (!ea)
                throw std::runtime_error(std::string("Invalid address in ") + key);
            return *ea;
        }

        json function_json(func_t *func) {
            return json{
                {"address", hex(func->start_ea)},
                {"name", utf8_clean(get_function_name(func))},
                {"size", hex(func->end_ea - func->start_ea)}
            };
        }

        json page(json items, int64 offset, int64 count) {
            const auto total = static_cast<int64>(items.size());
            if (offset < 0) offset = 0;
            const int64 end = count <= 0 ? total : std::min(total, offset + count);
            json data = json::array();
            for (int64 i = offset; i < end; ++i)
                data.push_back(std::move(items[static_cast<size_t>(i)]));
            return json{{"data", data}, {"next_offset", end < total ? json(end) : json(nullptr)}};
        }

        int64 int_param(const json &params, const char *key, int64 fallback) {
            return params.contains(key) && params[key].is_number_integer() ? params[key].get<int64>() : fallback;
        }

        json get_metadata(const json &) {
            char path[QMAXPATH] = {};
            get_input_file_path(path, sizeof(path));
            char module[QMAXPATH] = {};
            get_root_filename(module, sizeof(module));
            uchar digest[32] = {};
            if (!retrieve_input_file_sha256(digest))
                throw std::runtime_error("The database does not record the input file SHA-256");
            std::string sha256;
            for (uchar b: digest) {
                char buf[3];
                qsnprintf(buf, sizeof(buf), "%02x", b);
                sha256 += buf;
            }
            return json{
                {"path", utf8_clean(path)},
                {"module", utf8_clean(module)},
                {"sha256", sha256},
                {"base", hex(get_imagebase())}
            };
        }

        json list_functions(const json &params) {
            json items = json::array();
            for (size_t i = 0, n = get_func_qty(); i < n; ++i)
                if (func_t *func = getn_func(i))
                    items.push_back(function_json(func));
            return page(std::move(items), int_param(params, "offset", 0), int_param(params, "count", 100));
        }

        json list_strings(const json &params) {
            const int64 offset = int_param(params, "offset", 0);
            // Rebuild once per enumeration rather than once per page.
            if (offset == 0 || get_strlist_qty() == 0)
                build_strlist();
            json items = json::array();
            for (size_t i = 0, n = get_strlist_qty(); i < n; ++i) {
                string_info_t si;
                if (!get_strlist_item(&si, i))
                    continue;
                qstring contents;
                if (get_strlit_contents(&contents, si.ea, si.length, si.type) < 0)
                    continue;
                items.push_back(json{
                    {"address", hex(si.ea)},
                    {"length", si.length},
                    {"string", utf8_clean(contents.c_str())}
                });
            }
            return page(std::move(items), offset, int_param(params, "count", 100));
        }

        json get_function_by_name(const json &params) {
            if (!params.contains("name") || !params["name"].is_string())
                throw std::runtime_error("Missing required parameter: name");
            const std::string name = params["name"];
            ea_t ea = get_name_ea(BADADDR, name.c_str());
            func_t *func = ea == BADADDR ? nullptr : get_func(ea);
            if (func == nullptr)
                throw std::runtime_error("No function found with name " + name);
            return function_json(func);
        }

        json get_function_by_address(const json &params) {
            ea_t ea = require_ea(params, "address");
            func_t *func = get_func(ea);
            if (func == nullptr)
                throw std::runtime_error("No function found at address " + hex(ea));
            return function_json(func);
        }

        json disassemble_function(const json &params) {
            ea_t ea = require_ea(params, "start_address");
            func_t *func = get_func(ea);
            if (func == nullptr)
                throw std::runtime_error("No function found at address " + hex(ea));

            json lines = json::array();
            func_item_iterator_t fii;
            for (bool ok = fii.set(func); ok; ok = fii.next_code()) {
                ea_t item = fii.current();
                if (!is_code(get_flags(item)))
                    continue;
                qstring line;
                generate_disasm_line(&line, item, GENDSM_REMOVE_TAGS);
                lines.push_back(json{{"address", hex(item)}, {"instruction", utf8_clean(line.c_str())}});
            }

            json result = {
                {"name", utf8_clean(get_function_name(func))},
                {"start_ea", hex(func->start_ea)},
                {"lines", lines}
            };

            tinfo_t tif;
            func_type_data_t ftd;
            if (get_tinfo(&tif, func->start_ea) && tif.get_func_details(&ftd)) {
                qstring rettype;
                ftd.rettype.print(&rettype);
                json args = json::array();
                for (const funcarg_t &arg: ftd) {
                    qstring type;
                    arg.type.print(&type);
                    args.push_back(json{{"name", utf8_clean(arg.name.c_str())}, {"type", utf8_clean(type.c_str())}});
                }
                result["return_type"] = utf8_clean(rettype.c_str());
                result["arguments"] = args;
            }
            return result;
        }

        json get_callers(const json &params) {
            func_t *callee = get_func(require_ea(params, "function_address"));
            if (callee == nullptr)
                throw std::runtime_error("Address is not in a function");
            json result = json::array();
            std::set<ea_t> seen;
            xrefblk_t xb;
            for (bool ok = xb.first_to(callee->start_ea, XREF_NOFLOW); ok; ok = xb.next_to()) {
                if (!xb.iscode)
                    continue;
                insn_t insn;
                if (decode_insn(&insn, xb.from) <= 0 || !is_call_insn(insn))
                    continue;
                func_t *caller = get_func(xb.from);
                if (caller != nullptr && seen.insert(caller->start_ea).second)
                    result.push_back(function_json(caller));
            }
            return result;
        }

        json get_callees(const json &params) {
            func_t *func = get_func(require_ea(params, "function_address"));
            if (func == nullptr)
                throw std::runtime_error("Address is not in a function");
            json result = json::array();
            std::set<ea_t> seen;
            func_item_iterator_t fii;
            for (bool ok = fii.set(func); ok; ok = fii.next_code()) {
                ea_t item = fii.current();
                insn_t insn;
                if (decode_insn(&insn, item) <= 0 || !is_call_insn(insn))
                    continue;
                // Direct calls carry a code xref; calls through an import slot only a data xref.
                ea_t target = BADADDR;
                xrefblk_t xb;
                for (bool ok2 = xb.first_from(item, XREF_NOFLOW); ok2; ok2 = xb.next_from()) {
                    if (xb.iscode) {
                        target = xb.to;
                        break;
                    }
                    if (target == BADADDR)
                        target = xb.to;
                }
                if (target == BADADDR || !seen.insert(target).second)
                    continue;
                segment_t *seg = getseg(target);
                func_t *callee = get_func(target);
                if (callee != nullptr && (seg == nullptr || seg->type != SEG_XTRN)) {
                    json entry = function_json(callee);
                    entry["type"] = "internal";
                    result.push_back(entry);
                } else {
                    qstring name;
                    get_name(&name, target);
                    if (name.empty())
                        continue;
                    result.push_back(json{{"address", hex(target)}, {"name", utf8_clean(name.c_str())}, {"type", "external"}});
                }
            }
            return result;
        }

        json get_xrefs_to(const json &params) {
            ea_t ea = require_ea(params, "address");
            json result = json::array();
            xrefblk_t xb;
            for (bool ok = xb.first_to(ea, XREF_NOFLOW); ok; ok = xb.next_to()) {
                func_t *func = get_func(xb.from);
                result.push_back(json{
                    {"address", hex(xb.from)},
                    {"type", xb.iscode ? "code" : "data"},
                    {"function", func != nullptr ? function_json(func) : json(nullptr)}
                });
            }
            return result;
        }

        json object_schema(std::initializer_list<std::pair<const char *, const char *>> props,
                           std::initializer_list<const char *> required = {}) {
            json properties = json::object();
            for (const auto &[name, type]: props)
                properties[name] = json{{"type", type}};
            json schema = {{"type", "object"}, {"properties", properties}};
            if (required.size() != 0)
                schema["required"] = std::vector<std::string>(required.begin(), required.end());
            return schema;
        }

        void add(mcp::McpServer &server, const char *name, const char *description, json schema,
                 mcp::ToolHandler handler) {
            mcp::ToolDefinition def;
            def.name = name;
            def.description = description;
            def.input_schema = std::move(schema);
            def.annotations = mcp::ToolAnnotations{};
            def.annotations->read_only_hint = true;
            server.register_tool(def, std::move(handler));
        }
    }

    void register_tools(mcp::McpServer &server, const mcp::McpServer &main_server) {
        add(server, "get_metadata", "Input path, module, SHA-256 and image base of the open database",
            object_schema({}), get_metadata);
        add(server, "list_functions", "Page through all functions",
            object_schema({{"offset", "integer"}, {"count", "integer"}}), list_functions);
        add(server, "list_strings", "Page through the string list",
            object_schema({{"offset", "integer"}, {"count", "integer"}}), list_strings);
        add(server, "get_function_by_name", "Resolve a function by name",
            object_schema({{"name", "string"}}, {"name"}), get_function_by_name);
        add(server, "get_function_by_address", "Resolve the function containing an address",
            object_schema({{"address", "string"}}, {"address"}), get_function_by_address);
        add(server, "disassemble_function", "Disassemble a function",
            object_schema({{"start_address", "string"}}, {"start_address"}), disassemble_function);
        add(server, "get_callers", "Functions that call a function",
            object_schema({{"function_address", "string"}}, {"function_address"}), get_callers);
        add(server, "get_callees", "Functions and imports a function calls",
            object_schema({{"function_address", "string"}}, {"function_address"}), get_callees);
        add(server, "get_xrefs_to", "Cross-references to an address",
            object_schema({{"address", "string"}}, {"address"}), get_xrefs_to);

        // Reuse the main decompiler tool, keeping its extern, thunk and pathological-function guards.
        mcp::ToolHandler decompile = main_server.find_tool_handler("decompile_function");
        add(server, "decompile_function", "Hex-Rays pseudocode of a function, or null when decompilation fails",
            object_schema({{"address", "string"}}, {"address"}),
            [decompile](const json &params) -> json {
                if (!decompile)
                    return nullptr;
                try {
                    json result = decompile(params);
                    if (result.contains("pseudocode") && result["pseudocode"].is_string())
                        return utf8_clean(result["pseudocode"].get<std::string>());
                } catch (const std::exception &) {
                }
                return nullptr;
            });
    }
} // namespace ida_mcp::tools::rea_compat
