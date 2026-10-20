#include "tools/tools.hpp"
#include <segment.hpp>
#include <bytes.hpp>
#include <name.hpp>

namespace ida_mcp::tools::segment_manipulation {
    namespace {
        json handle_add_segment(const json &params) {
            auto start_opt = parse_ea(params["start"]);
            auto end_opt = parse_ea(params["end"]);
            if (!start_opt || !end_opt) throw std::runtime_error("Invalid address");

            std::string name = params.value("name", "");
            std::string sclass = params.value("class", "DATA");
            int perm = params.value("permissions", SEGPERM_READ | SEGPERM_WRITE);

            segment_t s;
            s.start_ea = start_opt.value();
            s.end_ea = end_opt.value();
            s.perm = perm;
            s.bitness = inf_is_64bit() ? 2 : (inf_is_32bit_or_higher() ? 1 : 0);
            s.type = SEG_DATA;
            s.align = saAbs;
            s.comb = scPub;

            if (sclass == "CODE") s.type = SEG_CODE;
            else if (sclass == "BSS") s.type = SEG_BSS;
            else if (sclass == "NORM") s.type = SEG_NORM;

            bool ok = add_segm_ex(&s, name.c_str(), sclass.c_str(), ADDSEG_OR_DIE);

            return json{
                {"start", format_ea(start_opt.value())},
                {"end", format_ea(end_opt.value())},
                {"name", name},
                {"class", sclass},
                {"success", ok}
            };
        }

        json handle_del_segment(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");

            segment_t *seg = getseg(ea_opt.value());
            if (!seg) throw std::runtime_error("No segment at " + format_ea(ea_opt.value()));

            qstring name;
            get_segm_name(&name, seg);
            int flags = params.value("flags", 0);
            bool ok = del_segm(ea_opt.value(), flags);

            return json{
                {"address", format_ea(ea_opt.value())},
                {"deleted_name", name.c_str()},
                {"success", ok}
            };
        }

        json handle_set_segment_name(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");

            segment_t *seg = getseg(ea_opt.value());
            if (!seg) throw std::runtime_error("No segment at " + format_ea(ea_opt.value()));

            std::string new_name = params["name"].get<std::string>();
            int ok = set_segm_name(seg, new_name.c_str());

            return json{
                {"address", format_ea(seg->start_ea)},
                {"name", new_name},
                {"success", ok == 1}
            };
        }

        json handle_set_segment_class(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");

            segment_t *seg = getseg(ea_opt.value());
            if (!seg) throw std::runtime_error("No segment at " + format_ea(ea_opt.value()));

            std::string new_class = params["class"].get<std::string>();
            int ok = set_segm_class(seg, new_class.c_str());

            return json{
                {"address", format_ea(seg->start_ea)},
                {"class", new_class},
                {"success", ok == 1}
            };
        }

        json handle_set_segment_bounds(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");

            segment_t *seg = getseg(ea_opt.value());
            if (!seg) throw std::runtime_error("No segment at " + format_ea(ea_opt.value()));

            json result;
            result["address"] = format_ea(seg->start_ea);

            if (params.contains("new_start")) {
                auto s = parse_ea(params["new_start"]);
                if (s) {
                    bool ok = set_segm_start(ea_opt.value(), s.value(), SEGMOD_KEEP);
                    result["set_start"] = ok;
                }
            }

            if (params.contains("new_end")) {
                auto e = parse_ea(params["new_end"]);
                if (e) {
                    bool ok = set_segm_end(ea_opt.value(), e.value(), SEGMOD_KEEP);
                    result["set_end"] = ok;
                }
            }

            return result;
        }

        json handle_set_segment_permissions(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");

            segment_t *seg = getseg(ea_opt.value());
            if (!seg) throw std::runtime_error("No segment at " + format_ea(ea_opt.value()));

            bool read = params.value("read", true);
            bool write = params.value("write", false);
            bool execute = params.value("execute", false);

            seg->perm = 0;
            if (read) seg->perm |= SEGPERM_READ;
            if (write) seg->perm |= SEGPERM_WRITE;
            if (execute) seg->perm |= SEGPERM_EXEC;

            seg->update();

            return json{
                {"address", format_ea(seg->start_ea)},
                {"permissions", {{"read", read}, {"write", write}, {"execute", execute}}},
                {"success", true}
            };
        }
    }

    void register_tools(mcp::McpServer &server) {
        {
            mcp::ToolDefinition def;
            def.name = "add_segment";
            def.description = "Create a new memory segment in the database";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"start", {{"type", "string"}, {"description", "Segment start address (hex)"}}},
                    {"end", {{"type", "string"}, {"description", "Segment end address (hex)"}}},
                    {"name", {{"type", "string"}, {"description", "Segment name"}}},
                    {"class", {{"type", "string"}, {"description", "Segment class: CODE/DATA/BSS/NORM"}}},
                    {"permissions", {{"type", "integer"}, {"description", "Permission flags (1=R, 2=W, 4=X, combine with |)"}}}
                }},
                {"required", json::array({"start", "end"})}
            };
            server.register_tool(def, handle_add_segment);
        }
        {
            mcp::ToolDefinition def;
            def.name = "delete_segment";
            def.description = "Delete a memory segment from the database";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Address within segment to delete"}}},
                    {"flags", {{"type", "integer"}, {"description", "Deletion flags (0=default)"}}}
                }},
                {"required", json::array({"address"})}
            };
            server.register_tool(def, handle_del_segment);
        }
        {
            mcp::ToolDefinition def;
            def.name = "set_segment_name";
            def.description = "Rename a segment";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Address within segment"}}},
                    {"name", {{"type", "string"}, {"description", "New segment name"}}}
                }},
                {"required", json::array({"address", "name"})}
            };
            server.register_tool(def, handle_set_segment_name);
        }
        {
            mcp::ToolDefinition def;
            def.name = "set_segment_class";
            def.description = "Change segment class (CODE/DATA/BSS/CONST/STACK/etc)";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Address within segment"}}},
                    {"class", {{"type", "string"}, {"description", "New segment class"}}}
                }},
                {"required", json::array({"address", "class"})}
            };
            server.register_tool(def, handle_set_segment_class);
        }
        {
            mcp::ToolDefinition def;
            def.name = "set_segment_bounds";
            def.description = "Change segment start and/or end address";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Address within segment"}}},
                    {"new_start", {{"type", "string"}, {"description", "New start address"}}},
                    {"new_end", {{"type", "string"}, {"description", "New end address"}}}
                }},
                {"required", json::array({"address"})}
            };
            server.register_tool(def, handle_set_segment_bounds);
        }
        {
            mcp::ToolDefinition def;
            def.name = "set_segment_permissions";
            def.description = "Set read/write/execute permissions on a segment";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Address within segment"}}},
                    {"read", {{"type", "boolean"}, {"description", "Readable (default true)"}}},
                    {"write", {{"type", "boolean"}, {"description", "Writable (default false)"}}},
                    {"execute", {{"type", "boolean"}, {"description", "Executable (default false)"}}}
                }},
                {"required", json::array({"address"})}
            };
            server.register_tool(def, handle_set_segment_permissions);
        }
    }
}
