#include "tools/tools.hpp"
#include <name.hpp>
#include <bytes.hpp>
#include <segment.hpp>
#include <xref.hpp>
#include <funcs.hpp>
#include <search.hpp>
#include <ua.hpp>

namespace ida_mcp::tools::objc_analysis {
    namespace {
        json handle_list_objc_selectors(const json &params) {
            segment_t *seg = get_segm_by_name("__objc_selrefs");
            if (!seg) seg = get_segm_by_name("__TEXT,__objc_selrefs");
            if (!seg) return json{{"error", "No __objc_selrefs segment"}, {"selectors", json::array()}};

            int limit = params.value("limit", 100);
            json selectors = json::array();

            for (ea_t ea = seg->start_ea; ea < seg->end_ea && (int)selectors.size() < limit; ea += sizeof(ea_t)) {
                ea_t str_ea = get_qword(ea);
                if (str_ea == 0 || str_ea == BADADDR) continue;

                qstring sel_name;
                get_strlit_contents(&sel_name, str_ea, get_max_strlit_length(str_ea, STRTYPE_C, 0), STRTYPE_C);
                if (sel_name.empty()) continue;

                json sel;
                sel["ref_address"] = format_ea(ea);
                sel["string_address"] = format_ea(str_ea);
                sel["name"] = sel_name.c_str();

                xrefblk_t xb;
                int xref_count = 0;
                for (bool ok = xb.first_to(ea, XREF_DATA); ok && xref_count < 50; ok = xb.next_to())
                    xref_count++;
                sel["usage_count"] = xref_count;

                selectors.push_back(sel);
            }

            return json{{"selector_count", selectors.size()}, {"selectors", selectors}};
        }

        json handle_list_objc_classes(const json &params) {
            segment_t *seg = get_segm_by_name("__objc_classrefs");
            if (!seg) seg = get_segm_by_name("__TEXT,__objc_classrefs");
            if (!seg) return json{{"error", "No __objc_classrefs segment"}, {"classes", json::array()}};

            int limit = params.value("limit", 100);
            json classes = json::array();

            for (ea_t ea = seg->start_ea; ea < seg->end_ea && (int)classes.size() < limit; ea += sizeof(ea_t)) {
                qstring name;
                get_ea_name(&name, ea);
                if (name.empty()) continue;

                ea_t class_ea = get_qword(ea);
                qstring class_name;
                if (class_ea != 0 && class_ea != BADADDR)
                    get_ea_name(&class_name, class_ea);

                json cls;
                cls["ref_address"] = format_ea(ea);
                cls["name"] = name.c_str();
                if (!class_name.empty())
                    cls["class_address"] = format_ea(class_ea);

                xrefblk_t xb;
                int xref_count = 0;
                for (bool ok = xb.first_to(ea, XREF_DATA); ok && xref_count < 50; ok = xb.next_to())
                    xref_count++;
                cls["usage_count"] = xref_count;

                classes.push_back(cls);
            }

            return json{{"class_count", classes.size()}, {"classes", classes}};
        }

        json handle_list_objc_methods(const json &params) {
            int limit = params.value("limit", 200);
            std::string filter = params.value("class_filter", "");

            json methods = json::array();
            size_t func_qty = get_func_qty();

            for (size_t i = 0; i < func_qty && (int)methods.size() < limit; i++) {
                func_t *func = getn_func(i);
                if (!func) continue;

                qstring name;
                if (get_func_name(&name, func->start_ea) <= 0) continue;

                const char *s = name.c_str();
                if (s[0] != '+' && s[0] != '-') continue;
                if (s[1] != '[') continue;

                if (!filter.empty() && name.find(filter.c_str()) == qstring::npos)
                    continue;

                json method;
                method["address"] = format_ea(func->start_ea);
                method["name"] = s;
                method["is_class_method"] = (s[0] == '+');
                method["is_instance_method"] = (s[0] == '-');
                method["size"] = func->size();

                const char *space = strchr(s + 2, ' ');
                if (space) {
                    qstring cls(s + 2, space - s - 2);
                    method["class"] = cls.c_str();

                    const char *bracket = strchr(space, ']');
                    if (bracket) {
                        qstring sel(space + 1, bracket - space - 1);
                        method["selector"] = sel.c_str();
                    }
                }

                methods.push_back(method);
            }

            return json{{"method_count", methods.size()}, {"methods", methods}};
        }

        json handle_list_objc_protocols(const json &params) {
            int limit = params.value("limit", 100);
            json protocols = json::array();

            segment_t *seg = get_segm_by_name("__objc_protolist");
            if (!seg) seg = get_segm_by_name("__DATA,__objc_protolist");
            if (!seg) seg = get_segm_by_name("__DATA_CONST,__objc_protolist");
            if (!seg) return json{{"error", "No __objc_protolist segment"}, {"protocols", json::array()}};

            for (ea_t ea = seg->start_ea; ea < seg->end_ea && (int)protocols.size() < limit; ea += sizeof(ea_t)) {
                ea_t proto_ea = get_qword(ea);
                if (proto_ea == 0 || proto_ea == BADADDR) continue;

                qstring name;
                get_ea_name(&name, proto_ea);

                json proto;
                proto["ref_address"] = format_ea(ea);
                proto["protocol_address"] = format_ea(proto_ea);
                proto["name"] = name.empty() ? json(nullptr) : json(name.c_str());
                protocols.push_back(proto);
            }

            return json{{"protocol_count", protocols.size()}, {"protocols", protocols}};
        }

        json handle_resolve_objc_call(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");
            ea_t ea = ea_opt.value();

            insn_t insn;
            if (decode_insn(&insn, ea) == 0)
                throw std::runtime_error("No instruction at " + format_ea(ea));

            qstring mnem, clean_dis;
            print_insn_mnem(&mnem, ea);

            qstring dis;
            generate_disasm_line(&dis, ea, GENDSM_FORCE_CODE);
            tag_remove(&clean_dis, dis);

            json result;
            result["address"] = format_ea(ea);
            result["mnemonic"] = mnem.c_str();
            result["disassembly"] = clean_dis.c_str();

            if (clean_dis.find("objc_msgSend") != qstring::npos) {
                result["is_objc_call"] = true;

                const char *dollar = strstr(clean_dis.c_str(), "$");
                if (dollar) {
                    result["selector"] = dollar + 1;

                    const char *semicolon = strstr(dollar, ";");
                    if (semicolon) {
                        qstring comment(semicolon + 1);
                        comment.trim2();
                        if (!comment.empty())
                            result["resolved_method"] = comment.c_str();
                    }
                }
            } else {
                result["is_objc_call"] = false;
            }

            return result;
        }

        json handle_get_xpc_services(const json &/*params*/) {
            json services = json::array();

            ea_t ea = inf_get_min_ea();
            while (ea != BADADDR) {
                ea = find_text(ea, 0, 0, "xpc_connection_create_mach_service",
                               SEARCH_DOWN | SEARCH_CASE | SEARCH_NOSHOW);
                if (ea == BADADDR) break;

                func_t *func = get_func(ea);
                qstring fname;
                if (func) get_func_name(&fname, func->start_ea);

                qstring dis, clean;
                generate_disasm_line(&dis, ea, GENDSM_FORCE_CODE);
                tag_remove(&clean, dis);

                services.push_back(json{
                    {"address", format_ea(ea)},
                    {"function", fname.empty() ? json(nullptr) : json(fname.c_str())},
                    {"disassembly", clean.c_str()}
                });

                ea = next_head(ea, inf_get_max_ea());
                if (ea == BADADDR) break;
            }

            return json{{"xpc_service_count", services.size()}, {"xpc_services", services}};
        }

        json handle_get_entitlements(const json &/*params*/) {
            json entitlements = json::array();

            segment_t *seg = get_segm_by_name("__info_plist");
            if (!seg) seg = get_segm_by_name("__TEXT,__info_plist");

            if (seg) {
                qstring plist;
                for (ea_t ea = seg->start_ea; ea < seg->end_ea; ea++) {
                    uint8 b = get_byte(ea);
                    if (b == 0) break;
                    plist.append((char)b);
                }
                if (!plist.empty())
                    entitlements.push_back(json{{"type", "info_plist"}, {"content", plist.c_str()}});
            }

            ea_t ea = inf_get_min_ea();
            while (ea != BADADDR) {
                ea = find_text(ea, 0, 0, "SecTaskCopyValueForEntitlement",
                               SEARCH_DOWN | SEARCH_CASE | SEARCH_NOSHOW);
                if (ea == BADADDR) break;

                func_t *func = get_func(ea);
                qstring fname;
                if (func) get_func_name(&fname, func->start_ea);

                entitlements.push_back(json{
                    {"type", "entitlement_check"},
                    {"address", format_ea(ea)},
                    {"function", fname.empty() ? json(nullptr) : json(fname.c_str())}
                });

                ea = next_head(ea, inf_get_max_ea());
                if (ea == BADADDR) break;
            }

            return json{{"entitlement_count", entitlements.size()}, {"entitlements", entitlements}};
        }
    }

    void register_tools(mcp::McpServer &server) {
        {
            mcp::ToolDefinition def;
            def.name = "list_objc_selectors";
            def.description = "List Objective-C selectors from __objc_selrefs with usage counts";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {{"limit", {{"type", "integer"}, {"description", "Max results (default 100)"}}}}}
            };
            server.register_tool(def, handle_list_objc_selectors);
        }
        {
            mcp::ToolDefinition def;
            def.name = "list_objc_classes";
            def.description = "List Objective-C class references from __objc_classrefs";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {{"limit", {{"type", "integer"}, {"description", "Max results (default 100)"}}}}}
            };
            server.register_tool(def, handle_list_objc_classes);
        }
        {
            mcp::ToolDefinition def;
            def.name = "list_objc_methods";
            def.description = "List Objective-C methods (+[Class method] and -[Class method]) found in the binary";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"limit", {{"type", "integer"}, {"description", "Max results (default 200)"}}},
                    {"class_filter", {{"type", "string"}, {"description", "Filter by class name substring"}}}
                }}
            };
            server.register_tool(def, handle_list_objc_methods);
        }
        {
            mcp::ToolDefinition def;
            def.name = "list_objc_protocols";
            def.description = "List Objective-C protocols from __objc_protolist";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {{"limit", {{"type", "integer"}, {"description", "Max results (default 100)"}}}}}
            };
            server.register_tool(def, handle_list_objc_protocols);
        }
        {
            mcp::ToolDefinition def;
            def.name = "resolve_objc_call";
            def.description = "Resolve an objc_msgSend call to its selector and target method";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {{"address", {{"type", "string"}, {"description", "Address of BL objc_msgSend instruction"}}}}},
                {"required", json::array({"address"})}
            };
            server.register_tool(def, handle_resolve_objc_call);
        }
        {
            mcp::ToolDefinition def;
            def.name = "get_xpc_services";
            def.description = "Find XPC service registrations (xpc_connection_create_mach_service calls)";
            def.input_schema = json{{"type", "object"}, {"properties", json::object()}};
            server.register_tool(def, handle_get_xpc_services);
        }
        {
            mcp::ToolDefinition def;
            def.name = "get_entitlements";
            def.description = "Extract embedded Info.plist and find entitlement checks (SecTaskCopyValueForEntitlement)";
            def.input_schema = json{{"type", "object"}, {"properties", json::object()}};
            server.register_tool(def, handle_get_entitlements);
        }
    }
}
