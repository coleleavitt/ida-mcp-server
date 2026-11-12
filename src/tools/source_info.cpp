#include "tools/tools.hpp"
#include <lines.hpp>
#include <funcs.hpp>
#include <loader.hpp>
#include <diskio.hpp>
#include <name.hpp>
#include <tryblks.hpp>
#include <tryblks.hpp>

namespace ida_mcp::tools::source_info {
    namespace {
        json handle_get_source_file(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");
            ea_t ea = ea_opt.value();

            range_t bounds;
            const char *src = get_sourcefile(ea, &bounds);
            if (src != nullptr) {
                return json{
                    {"address", format_ea(ea)},
                    {"source_file", src},
                    {"range_start", format_ea(bounds.start_ea)},
                    {"range_end", format_ea(bounds.end_ea)},
                    {"found", true}
                };
            }

            return json{
                {"address", format_ea(ea)},
                {"found", false}
            };
        }

        json handle_get_source_line(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");
            ea_t ea = ea_opt.value();

            int line = get_source_linnum(ea);

            return json{
                {"address", format_ea(ea)},
                {"line_number", line > 0 ? json(line) : json(nullptr)},
                {"found", line > 0}
            };
        }

        json handle_get_input_file_info(const json &/*params*/) {
            char root[QMAXPATH] = {0};
            get_root_filename(root, sizeof(root));

            char loader[256] = {0};
            get_loader_name(loader, sizeof(loader));

            filetype_t ft = inf_get_filetype();
            ea_t imagebase = inf_get_min_ea();
            ea_t start = inf_get_start_ea();

            int seg_count = get_segm_qty();

            return json{
                {"filename", root},
                {"loader", loader},
                {"filetype", static_cast<int>(ft)},
                {"imagebase", format_ea(imagebase)},
                {"start_address", format_ea(start)},
                {"segment_count", seg_count},
                {"is_64bit", inf_is_64bit()},
                {"is_32bit", inf_is_32bit_or_higher()},
                {"is_big_endian", inf_is_be()}
            };
        }

        json handle_get_idb_path(const json &/*params*/) {
            const char *idb = get_path(PATH_TYPE_IDB);
            const char *cmd = get_path(PATH_TYPE_CMD);
            const char *id0 = get_path(PATH_TYPE_ID0);

            const char *ida_root = idadir(nullptr);
            const char *userdir = get_user_idadir();

            return json{
                {"idb_path", idb ? json(idb) : json(nullptr)},
                {"ida_command", cmd ? json(cmd) : json(nullptr)},
                {"id0_path", id0 ? json(id0) : json(nullptr)},
                {"ida_directory", ida_root ? json(ida_root) : json(nullptr)},
                {"user_directory", userdir ? json(userdir) : json(nullptr)}
            };
        }

        json handle_get_tryblks(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");
            ea_t ea = ea_opt.value();

            func_t *func = get_func(ea);
            if (!func) throw std::runtime_error("No function at " + format_ea(ea));

            tryblks_t tryblks;
            range_t range(func->start_ea, func->end_ea);
            size_t count = get_tryblks(&tryblks, range);

            json blocks = json::array();
            for (size_t i = 0; i < tryblks.size(); i++) {
                tryblk_t &tb = tryblks[i];
                json block;
                block["level"] = tb.level;

                if (tb.size() > 0) {
                    block["range_start"] = format_ea(tb[0].start_ea);
                    block["range_end"] = format_ea(tb[0].end_ea);
                }

                if (tb.is_cpp()) {
                    block["kind"] = "cpp";
                    catchvec_t &cv = tb.cpp();
                    json catches = json::array();
                    for (size_t j = 0; j < cv.size(); j++) {
                        catch_t &c = cv[j];
                        json ce;
                        ce["obj_offset"] = (int64_t)c.obj;
                        ce["type_id"] = (int64_t)c.type_id;
                        ce["is_catch_all"] = (c.type_id == CATCH_ID_ALL);
                        ce["disp"] = (int64_t)c.disp;
                        json ranges = json::array();
                        for (size_t k = 0; k < c.size(); k++) {
                            ranges.push_back(json{
                                {"start", format_ea(c[k].start_ea)},
                                {"end", format_ea(c[k].end_ea)}
                            });
                        }
                        ce["ranges"] = ranges;
                        catches.push_back(ce);
                    }
                    block["catches"] = catches;
                } else if (tb.is_seh()) {
                    block["kind"] = "seh";
                    const seh_t &seh = tb.seh();
                    block["seh_code"] = format_ea(seh.seh_code);
                    block["disp"] = (int64_t)seh.disp;
                    json filter_ranges = json::array();
                    for (size_t k = 0; k < seh.filter.size(); k++) {
                        filter_ranges.push_back(json{
                            {"start", format_ea(seh.filter[k].start_ea)},
                            {"end", format_ea(seh.filter[k].end_ea)}
                        });
                    }
                    block["filter_ranges"] = filter_ranges;
                    json handler_ranges = json::array();
                    for (size_t k = 0; k < seh.size(); k++) {
                        handler_ranges.push_back(json{
                            {"start", format_ea(seh[k].start_ea)},
                            {"end", format_ea(seh[k].end_ea)}
                        });
                    }
                    block["handler_ranges"] = handler_ranges;
                } else {
                    block["kind"] = "unknown";
                }

                blocks.push_back(block);
            }

            qstring func_name;
            get_func_name(&func_name, func->start_ea);

            return json{
                {"function", func_name.c_str()},
                {"function_address", format_ea(func->start_ea)},
                {"tryblk_count", count},
                {"tryblks", blocks}
            };
        }
    }

    void register_tools(mcp::McpServer &server) {
        {
            mcp::ToolDefinition def;
            def.name = "get_source_file";
            def.description = "Get the source file associated with an address (from debug info/DWARF)";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Hex address"}}}
                }},
                {"required", json::array({"address"})}
            };
            server.register_tool(def, handle_get_source_file);
        }
        {
            mcp::ToolDefinition def;
            def.name = "get_source_line";
            def.description = "Get the source line number for an address (from debug info/DWARF)";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Hex address"}}}
                }},
                {"required", json::array({"address"})}
            };
            server.register_tool(def, handle_get_source_line);
        }
        {
            mcp::ToolDefinition def;
            def.name = "get_input_file_info";
            def.description = "Get information about the original input file (name, loader, type, base address)";
            def.input_schema = json{
                {"type", "object"},
                {"properties", json::object()}
            };
            server.register_tool(def, handle_get_input_file_info);
        }
        {
            mcp::ToolDefinition def;
            def.name = "get_idb_paths";
            def.description = "Get IDA database paths (IDB, ID0, IDA installation directory, user config directory)";
            def.input_schema = json{
                {"type", "object"},
                {"properties", json::object()}
            };
            server.register_tool(def, handle_get_idb_path);
        }
        {
            mcp::ToolDefinition def;
            def.name = "get_exception_handlers";
            def.description = "Get try/catch exception handling blocks for a function (C++ EH, SEH)";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Address within function"}}}
                }},
                {"required", json::array({"address"})}
            };
            server.register_tool(def, handle_get_tryblks);
        }
    }
}
