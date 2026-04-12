#include "tools/tools.hpp"
#include <bytes.hpp>
#include <segment.hpp>
#include <name.hpp>
#include <funcs.hpp>
#include <xref.hpp>
#include <typeinf.hpp>
#include <fixup.hpp>

// ObjC2 ARM64 runtime struct layouts (from Apple objc4 source + objc.so RE)
// class_ro_t (64-bit):
//   +0x00: uint32 flags
//   +0x04: uint32 instanceStart
//   +0x08: uint32 instanceSize
//   +0x0C: uint32 reserved
//   +0x10: ptr    ivarLayout
//   +0x18: ptr    name
//   +0x20: ptr    baseMethods (method_list_t*)
//   +0x28: ptr    baseProtocols
//   +0x30: ptr    ivars (ivar_list_t*)
//   +0x38: ptr    weakIvarLayout
//   +0x40: ptr    baseProperties
//
// method_t (64-bit):
//   +0x00: ptr    name (SEL)
//   +0x08: ptr    types
//   +0x10: ptr    imp (IMP)
//
// ivar_t (64-bit):
//   +0x00: ptr    offset
//   +0x08: ptr    name
//   +0x10: ptr    type
//   +0x18: uint32 alignment_raw
//   +0x1C: uint32 size

namespace ida_mcp::tools::objc_deep {
    namespace {
        qstring read_string_at(ea_t ea) {
            qstring s;
            if (ea != 0 && ea != BADADDR)
                get_strlit_contents(&s, ea, get_max_strlit_length(ea, STRTYPE_C, 0), STRTYPE_C);
            return s;
        }

        json handle_get_objc_class_info(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");
            ea_t ea = ea_opt.value();

            json result;
            result["address"] = format_ea(ea);

            qstring ea_name;
            get_ea_name(&ea_name, ea);
            result["ida_name"] = ea_name.empty() ? json(nullptr) : json(ea_name.c_str());

            ea_t isa = get_qword(ea);
            ea_t superclass = get_qword(ea + 8);
            ea_t cache = get_qword(ea + 0x10);
            ea_t vtable = get_qword(ea + 0x18);
            ea_t data = get_qword(ea + 0x20);

            ea_t ro_ptr = data & ~7ULL;

            result["isa"] = isa != 0 ? json(format_ea(isa)) : json(nullptr);
            result["superclass"] = superclass != 0 ? json(format_ea(superclass)) : json(nullptr);
            result["data_ptr"] = format_ea(ro_ptr);

            if (ro_ptr == 0 || ro_ptr == BADADDR || !is_loaded(ro_ptr))
                return result;

            uint32 flags = get_dword(ro_ptr);
            uint32 instance_start = get_dword(ro_ptr + 4);
            uint32 instance_size = get_dword(ro_ptr + 8);
            ea_t name_ptr = get_qword(ro_ptr + 0x18);
            ea_t methods_ptr = get_qword(ro_ptr + 0x20);
            ea_t protocols_ptr = get_qword(ro_ptr + 0x28);
            ea_t ivars_ptr = get_qword(ro_ptr + 0x30);
            ea_t properties_ptr = get_qword(ro_ptr + 0x40);

            qstring class_name = read_string_at(name_ptr);
            result["class_name"] = class_name.empty() ? json(nullptr) : json(class_name.c_str());
            result["flags"] = flags;
            result["instance_start"] = instance_start;
            result["instance_size"] = instance_size;
            result["is_meta"] = (flags & 1) != 0;
            result["is_root"] = (flags & 2) != 0;
            result["has_cxx_ctor"] = (flags & (1 << 18)) != 0;

            if (methods_ptr != 0 && methods_ptr != BADADDR && is_loaded(methods_ptr)) {
                uint32 method_flags = get_dword(methods_ptr);
                uint32 method_count = get_dword(methods_ptr + 4);
                bool uses_relative = (method_flags & 0x80000000) != 0;
                method_count &= 0x00FFFFFF;

                json methods = json::array();
                ea_t entry = methods_ptr + 8;

                for (uint32 i = 0; i < method_count && i < 200; i++) {
                    json m;
                    if (uses_relative) {
                        int32 name_off = get_dword(entry);
                        int32 types_off = get_dword(entry + 4);
                        int32 imp_off = get_dword(entry + 8);
                        ea_t sel_ea = entry + name_off;
                        ea_t sel_ptr = get_qword(sel_ea);
                        qstring sel_name = read_string_at(sel_ptr);
                        m["selector"] = sel_name.empty() ? json(nullptr) : json(sel_name.c_str());
                        m["imp"] = format_ea(entry + 8 + imp_off);
                        entry += 12;
                    } else {
                        ea_t sel = get_qword(entry);
                        ea_t types = get_qword(entry + 8);
                        ea_t imp = get_qword(entry + 0x10);
                        qstring sel_name = read_string_at(sel);
                        qstring type_str = read_string_at(types);
                        m["selector"] = sel_name.empty() ? json(nullptr) : json(sel_name.c_str());
                        m["types"] = type_str.empty() ? json(nullptr) : json(type_str.c_str());
                        m["imp"] = format_ea(imp);

                        func_t *f = get_func(imp);
                        if (f) {
                            qstring fname;
                            get_func_name(&fname, f->start_ea);
                            if (!fname.empty()) m["imp_name"] = fname.c_str();
                        }
                        entry += 0x18;
                    }
                    methods.push_back(m);
                }
                result["method_count"] = method_count;
                result["methods"] = methods;
                result["uses_relative_methods"] = uses_relative;
            }

            if (ivars_ptr != 0 && ivars_ptr != BADADDR && is_loaded(ivars_ptr)) {
                uint32 ivar_size = get_dword(ivars_ptr);
                uint32 ivar_count = get_dword(ivars_ptr + 4);

                json ivars = json::array();
                ea_t entry = ivars_ptr + 8;
                for (uint32 i = 0; i < ivar_count && i < 200; i++) {
                    ea_t offset_ptr = get_qword(entry);
                    ea_t name_p = get_qword(entry + 8);
                    ea_t type_p = get_qword(entry + 0x10);
                    uint32 align = get_dword(entry + 0x18);
                    uint32 size = get_dword(entry + 0x1C);

                    qstring iname = read_string_at(name_p);
                    qstring itype = read_string_at(type_p);
                    uint32 offset_val = offset_ptr ? get_dword(offset_ptr) : 0;

                    json iv;
                    iv["name"] = iname.empty() ? json(nullptr) : json(iname.c_str());
                    iv["type"] = itype.empty() ? json(nullptr) : json(itype.c_str());
                    iv["offset"] = offset_val;
                    iv["size"] = size;
                    ivars.push_back(iv);
                    entry += 0x20;
                }
                result["ivar_count"] = ivar_count;
                result["ivars"] = ivars;
            }

            if (superclass != 0 && superclass != BADADDR && is_loaded(superclass)) {
                qstring super_name;
                get_ea_name(&super_name, superclass);
                result["superclass_name"] = super_name.empty() ? json(nullptr) : json(super_name.c_str());
            }

            return result;
        }

        json handle_get_vtable(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");
            ea_t ea = ea_opt.value();
            int limit = params.value("limit", 50);

            json entries = json::array();
            for (int i = 0; i < limit; i++) {
                ea_t slot = ea + i * sizeof(ea_t);
                if (!is_loaded(slot)) break;

                ea_t target = get_qword(slot);
                if (target == 0) break;

                func_t *f = get_func(target);
                if (!f && i > 0) break;

                json entry;
                entry["index"] = i;
                entry["slot_address"] = format_ea(slot);
                entry["target"] = format_ea(target);

                if (f) {
                    qstring fname;
                    get_func_name(&fname, f->start_ea);
                    if (!fname.empty()) entry["name"] = fname.c_str();
                }

                qstring ea_name;
                get_ea_name(&ea_name, slot);
                if (!ea_name.empty()) entry["slot_name"] = ea_name.c_str();

                entries.push_back(entry);
            }

            qstring vtable_name;
            get_ea_name(&vtable_name, ea);

            return json{
                {"address", format_ea(ea)},
                {"name", vtable_name.empty() ? json(nullptr) : json(vtable_name.c_str())},
                {"entry_count", entries.size()},
                {"entries", entries}
            };
        }

        json handle_get_chained_fixups(const json &params) {
            auto ea_opt = parse_ea(params.value("address", "0"));
            int limit = params.value("limit", 100);

            json fixups = json::array();
            ea_t ea = ea_opt.value_or(inf_get_min_ea());

            ea_t fixup_ea = get_first_fixup_ea();
            int count = 0;
            while (fixup_ea != BADADDR && count < limit) {
                fixup_data_t fd;
                if (get_fixup(&fd, fixup_ea)) {
                    json f;
                    f["address"] = format_ea(fixup_ea);
                    f["type"] = fd.get_type();

                    qstring target_name;
                    ea_t target = get_fixup_value(fixup_ea, fd.get_type());
                    if (target != BADADDR) {
                        f["target"] = format_ea(target);
                        get_ea_name(&target_name, target);
                        if (!target_name.empty())
                            f["target_name"] = target_name.c_str();
                    }

                    fixups.push_back(f);
                }
                fixup_ea = get_next_fixup_ea(fixup_ea);
                count++;
            }

            return json{
                {"fixup_count", fixups.size()},
                {"fixups", fixups}
            };
        }

        json handle_get_decompiler_call_info(const json &params) {
            auto ea_opt = parse_ea(params["address"]);
            if (!ea_opt) throw std::runtime_error("Invalid address");
            ea_t ea = ea_opt.value();

            func_t *func = get_func(ea);
            if (!func) throw std::runtime_error("No function at " + format_ea(ea));

            json result;
            result["address"] = format_ea(ea);

            qstring fname;
            get_func_name(&fname, func->start_ea);
            result["function"] = fname.c_str();

            tinfo_t tif;
            if (get_tinfo(&tif, func->start_ea) || guess_tinfo(&tif, func->start_ea)) {
                qstring type_str;
                tif.print(&type_str);
                result["type"] = type_str.c_str();

                func_type_data_t ftd;
                if (tif.get_func_details(&ftd)) {
                    result["calling_convention"] = ftd.get_cc() & CM_CC_MASK;
                    result["arg_count"] = ftd.size();
                    result["is_noret"] = (func->flags & FUNC_NORET) != 0;

                    json args = json::array();
                    for (size_t i = 0; i < ftd.size() && i < 20; i++) {
                        funcarg_t &arg = ftd[i];
                        json a;
                        if (!arg.name.empty())
                            a["name"] = arg.name.c_str();

                        qstring atype;
                        arg.type.print(&atype);
                        a["type"] = atype.c_str();

                        args.push_back(a);
                    }
                    result["args"] = args;

                    qstring rettype;
                    ftd.rettype.print(&rettype);
                    result["return_type"] = rettype.c_str();
                }
            }

            result["is_thunk"] = (func->flags & FUNC_THUNK) != 0;
            result["is_noret"] = (func->flags & FUNC_NORET) != 0;
            result["func_size"] = func->size();

            return result;
        }
    }

    void register_tools(mcp::McpServer &server) {
        {
            mcp::ToolDefinition def;
            def.name = "get_objc_class_info";
            def.description =
                "Deep ObjC class analysis — read class_ro_t struct to get methods, ivars, "
                "properties, superclass, flags. Pass the address of an ObjC class struct.";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {{"address", {{"type", "string"}, {"description", "Address of ObjC class struct (from __objc_classrefs or __objc_intobj)"}}}}},
                {"required", json::array({"address"})}
            };
            server.register_tool(def, handle_get_objc_class_info);
        }
        {
            mcp::ToolDefinition def;
            def.name = "get_vtable_entries";
            def.description = "Read vtable/vftable entries — list function pointers at a vtable address";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Vtable start address"}}},
                    {"limit", {{"type", "integer"}, {"description", "Max entries to read (default 50)"}}}
                }},
                {"required", json::array({"address"})}
            };
            server.register_tool(def, handle_get_vtable);
        }
        {
            mcp::ToolDefinition def;
            def.name = "get_chained_fixups";
            def.description = "List chained fixups/relocations (LC_DYLD_CHAINED_FIXUPS) in the binary";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Start address (default: beginning)"}}},
                    {"limit", {{"type", "integer"}, {"description", "Max fixups (default 100)"}}}
                }}
            };
            server.register_tool(def, handle_get_chained_fixups);
        }
        {
            mcp::ToolDefinition def;
            def.name = "get_call_info";
            def.description =
                "Get rich call/function metadata — type signature, args, return type, "
                "calling convention, stack delta, thunk/noret flags, frame size";
            def.input_schema = json{
                {"type", "object"},
                {"properties", {{"address", {{"type", "string"}, {"description", "Function or call site address"}}}}},
                {"required", json::array({"address"})}
            };
            server.register_tool(def, handle_get_decompiler_call_info);
        }
    }
}
