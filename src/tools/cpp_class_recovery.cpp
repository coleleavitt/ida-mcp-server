// Itanium C++ ABI class / vtable recovery tool.
//
// One-shot pre-pass that scans the binary for typeinfo nodes (RTTI), parses
// the class hierarchy, names vtables, and renames virtual methods. Subsequent
// decompile_function calls then automatically benefit because Hex-Rays uses
// the class types stored in the IDB.
//
// Itanium ABI vtable layout (Linux/macOS GCC/Clang):
//   [-2 ptr] offset_to_top   (signed; 0 for primary vtable)
//   [-1 ptr] RTTI pointer    -> _ZTI<mangled> typeinfo struct
//   [ 0 ptr] vfunc[0]        <- vptr in object points HERE (the address point)
//   [ 1 ptr] vfunc[1]
//   ...
//
// typeinfo struct (3 variants; first field always identifies the variant):
//   [+0x00] vtable_ptr -> _ZTVN10__cxxabiv1{17|20|21}E + 16
//             N=17 -> __class_type_info     (no inheritance)
//             N=20 -> __si_class_type_info  (single inheritance)
//             N=21 -> __vmi_class_type_info (multiple/virtual inheritance)
//   [+0x08] name_ptr   -> _ZTS<mangled> name string
//   [+0x10] base_typeinfo_ptr (si_class only)
//         | flags (4) + base_count (4) + base_info[]{tinfo_ptr, offset_flags} (vmi)
//
// Spec: https://itanium-cxx-abi.github.io/cxx-abi/abi.html#rtti
// LLVM impl: clang/lib/CodeGen/ItaniumCXXABI.cpp:4193-4564

#include "tools/tools.hpp"

#include <bytes.hpp>
#include <demangle.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <segment.hpp>
#include <typeinf.hpp>
#include <xref.hpp>

#include <cctype>
#include <cstring>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace ida_mcp::tools::cpp_class_recovery {
namespace {

constexpr const char *kCxxabivClassTypeinfoVtable    = "_ZTVN10__cxxabiv117__class_type_infoE";
constexpr const char *kCxxabivSiClassTypeinfoVtable  = "_ZTVN10__cxxabiv120__si_class_type_infoE";
constexpr const char *kCxxabivVmiClassTypeinfoVtable = "_ZTVN10__cxxabiv121__vmi_class_type_infoE";

// On x86-64 the vtable address point lives 2 pointers (16 bytes) past the
// vtable symbol's start. Constant for the entire Itanium ABI on 64-bit targets.
constexpr ea_t kAddrPointOffset = 16;
constexpr ea_t kPtrSize = 8;

enum class TypeInfoKind {
    Class,    // __class_type_info     (leaf - no bases)
    SiClass,  // __si_class_type_info  (single base)
    VmiClass  // __vmi_class_type_info (multiple/virtual bases)
};

struct TypeInfoNode {
    ea_t address = BADADDR;
    TypeInfoKind kind = TypeInfoKind::Class;
    qstring class_name;          // demangled (e.g. "std::vector<int>")
    qstring mangled_zts;         // raw _ZTS string (e.g. "St6vectorIiSaIiEE")
    std::vector<ea_t> bases;     // parent typeinfo addresses
};

struct VTableInfo {
    ea_t address = BADADDR;      // address point (vfunc[0])
    ea_t typeinfo = BADADDR;
    int64_t offset_to_top = 0;
    std::vector<ea_t> vfuncs;
};

bool detect_itanium_abi() {
    return get_name_ea(BADADDR, kCxxabivClassTypeinfoVtable) != BADADDR
        || get_name_ea(BADADDR, kCxxabivSiClassTypeinfoVtable) != BADADDR
        || get_name_ea(BADADDR, kCxxabivVmiClassTypeinfoVtable) != BADADDR;
}

qstring read_zts_string(ea_t ea) {
    qstring s;
    get_strlit_contents(&s, ea, -1, STRTYPE_C);
    return s;
}

qstring demangle_zts_to_classname(const qstring &zts) {
    qstring buf;
    std::string mangled = "_ZTI";
    mangled += zts.c_str();
    if (demangle_name(&buf, mangled.c_str(), MNG_LONG_FORM) > 0) {
        std::string s(buf.c_str(), buf.size());
        for (const char *prefix : {"typeinfo for ", "`typeinfo for'", "typeinfo for `"}) {
            const size_t plen = std::strlen(prefix);
            if (s.size() >= plen && s.compare(0, plen, prefix) == 0) {
                s.erase(0, plen);
                break;
            }
        }
        while (!s.empty() && (s.front() == '`' || s.front() == '\'')) s.erase(0, 1);
        while (!s.empty() && (s.back()  == '`' || s.back()  == '\'')) s.pop_back();
        return qstring(s.c_str(), s.size());
    }
    return zts;
}

std::optional<TypeInfoKind> classify_typeinfo_metaclass(ea_t metaclass_vtable_addr) {
    // The first field of every typeinfo node points to the address point of one
    // of the three __cxxabiv1 metaclass vtables. Subtract 16 to get the vtable
    // symbol itself, then read the symbol name to identify which variant.
    if (metaclass_vtable_addr < kAddrPointOffset) return std::nullopt;

    qstring name;
    if (get_name(&name, metaclass_vtable_addr - kAddrPointOffset) <= 0)
        return std::nullopt;

    if (name == kCxxabivClassTypeinfoVtable)    return TypeInfoKind::Class;
    if (name == kCxxabivSiClassTypeinfoVtable)  return TypeInfoKind::SiClass;
    if (name == kCxxabivVmiClassTypeinfoVtable) return TypeInfoKind::VmiClass;
    return std::nullopt;
}

std::optional<TypeInfoNode> try_parse_typeinfo(ea_t ea) {
    if (!is_loaded(ea)) return std::nullopt;

    ea_t metaclass_vt = get_qword(ea);
    if (!is_loaded(metaclass_vt)) return std::nullopt;

    auto kind_opt = classify_typeinfo_metaclass(metaclass_vt);
    if (!kind_opt) return std::nullopt;

    ea_t name_ptr = get_qword(ea + kPtrSize);
    if (!is_loaded(name_ptr)) return std::nullopt;

    qstring zts = read_zts_string(name_ptr);
    if (zts.empty()) return std::nullopt;

    TypeInfoNode node;
    node.address = ea;
    node.kind = *kind_opt;
    node.mangled_zts = zts;
    node.class_name = demangle_zts_to_classname(zts);

    if (node.kind == TypeInfoKind::SiClass) {
        ea_t base = get_qword(ea + 2 * kPtrSize);
        if (is_loaded(base)) node.bases.push_back(base);
    } else if (node.kind == TypeInfoKind::VmiClass) {
        // [+0x10] flags (4 bytes) | [+0x14] base_count (4 bytes)
        // [+0x18..] base_info[i] = { typeinfo_ptr (8), offset_flags (8) }
        uint32 base_count = get_dword(ea + 2 * kPtrSize + 4);
        for (uint32 i = 0; i < base_count && i < 64; i++) {
            ea_t base = get_qword(ea + 3 * kPtrSize + i * 16);
            if (is_loaded(base)) node.bases.push_back(base);
        }
    }

    return node;
}

std::vector<TypeInfoNode> find_all_typeinfo_nodes() {
    std::vector<TypeInfoNode> nodes;
    std::set<ea_t> seen;

    std::set<ea_t> metaclass_addr_pts;
    for (const char *vt_name : {
        kCxxabivClassTypeinfoVtable,
        kCxxabivSiClassTypeinfoVtable,
        kCxxabivVmiClassTypeinfoVtable
    }) {
        ea_t vt_ea = get_name_ea(BADADDR, vt_name);
        if (vt_ea == BADADDR) continue;
        metaclass_addr_pts.insert(vt_ea + kAddrPointOffset);
    }
    if (metaclass_addr_pts.empty()) return nodes;

    for (segment_t *seg = get_first_seg(); seg != nullptr; seg = get_next_seg(seg->start_ea)) {
        if ((seg->perm & SEGPERM_WRITE) == 0 && seg->type != SEG_DATA) continue;
        if (seg->perm & SEGPERM_EXEC) continue;

        qstring sname;
        get_segm_name(&sname, seg);
        const bool is_candidate_seg =
            sname == ".data.rel.ro"
            || sname == ".data.rel.ro.local"
            || sname == ".rodata"
            || sname == ".rdata"
            || sname == "__const"
            || sname == "__DATA_CONST"
            || (seg->type == SEG_DATA);
        if (!is_candidate_seg) continue;

        ea_t end = seg->end_ea;
        if (end < kPtrSize) continue;
        end -= kPtrSize;
        for (ea_t ea = seg->start_ea; ea < end; ea += kPtrSize) {
            ea_t v = get_qword(ea);
            if (metaclass_addr_pts.find(v) == metaclass_addr_pts.end()) continue;
            if (!seen.insert(ea).second) continue;
            if (auto node = try_parse_typeinfo(ea)) {
                nodes.push_back(*node);
            }
        }
    }

    return nodes;
}

std::vector<VTableInfo> find_vtables_for_typeinfo_set(const std::set<ea_t> &typeinfo_addrs) {
    std::vector<VTableInfo> result;
    std::set<ea_t> seen;

    for (segment_t *seg = get_first_seg(); seg != nullptr; seg = get_next_seg(seg->start_ea)) {
        if ((seg->perm & SEGPERM_WRITE) == 0 && seg->type != SEG_DATA) continue;
        if (seg->perm & SEGPERM_EXEC) continue;

        qstring sname;
        get_segm_name(&sname, seg);
        const bool is_candidate_seg =
            sname == ".data.rel.ro"
            || sname == ".data.rel.ro.local"
            || sname == ".rodata"
            || sname == ".rdata"
            || sname == "__const"
            || sname == "__DATA_CONST"
            || (seg->type == SEG_DATA);
        if (!is_candidate_seg) continue;

        ea_t end = seg->end_ea;
        if (end < kPtrSize) continue;
        end -= kPtrSize;
        for (ea_t ea = seg->start_ea; ea < end; ea += kPtrSize) {
            ea_t v = get_qword(ea);
            if (typeinfo_addrs.find(v) == typeinfo_addrs.end()) continue;
            ea_t rtti_slot = ea;
            if (!seen.insert(rtti_slot).second) continue;
            if (rtti_slot < kPtrSize) continue;

            ea_t addr_pt = rtti_slot + kPtrSize;
            VTableInfo vt;
            vt.address = addr_pt;
            vt.typeinfo = v;
            vt.offset_to_top = static_cast<int64_t>(get_qword(rtti_slot - kPtrSize));

            for (int i = 0; i < 256; i++) {
                ea_t slot = addr_pt + i * kPtrSize;
                if (!is_loaded(slot)) break;
                ea_t target = get_qword(slot);
                if (target == 0) break;
                segment_t *tseg = getseg(target);
                if (tseg == nullptr) break;
                if (!(tseg->perm & SEGPERM_EXEC)) break;
                vt.vfuncs.push_back(target);
            }

            if (!vt.vfuncs.empty()) result.push_back(std::move(vt));
        }
    }

    return result;
}

std::vector<VTableInfo> find_vtables_for_typeinfo(ea_t typeinfo_ea) {
    std::vector<VTableInfo> result;

    xrefblk_t xb;
    for (bool ok = xb.first_to(typeinfo_ea, XREF_DATA); ok; ok = xb.next_to()) {
        ea_t rtti_slot = xb.from;
        if (rtti_slot < kPtrSize) continue;

        // The address point starts immediately after the RTTI pointer.
        ea_t addr_pt = rtti_slot + kPtrSize;

        VTableInfo vt;
        vt.address = addr_pt;
        vt.typeinfo = typeinfo_ea;
        vt.offset_to_top = static_cast<int64_t>(get_qword(rtti_slot - kPtrSize));

        for (int i = 0; i < 256; i++) {
            ea_t slot = addr_pt + i * kPtrSize;
            if (!is_loaded(slot)) break;
            ea_t target = get_qword(slot);
            if (target == 0) break;

            // Stop if target isn't in an executable segment.
            segment_t *seg = getseg(target);
            if (seg == nullptr) break;
            if (!(seg->perm & SEGPERM_EXEC)) break;

            vt.vfuncs.push_back(target);
        }

        if (!vt.vfuncs.empty()) result.push_back(vt);
    }

    return result;
}

std::string sanitize_ident(const qstring &raw) {
    std::string out;
    out.reserve(raw.size());
    for (char c : std::string_view(raw.c_str(), raw.size())) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_') {
            out.push_back(c);
        } else if (c == ':' && !out.empty() && out.back() == ':') {
            out.push_back(c);
        } else if (c == ':') {
            out.push_back(c);
        } else {
            out.push_back('_');
        }
    }
    return out;
}

struct ApplyStats {
    int classes_recovered = 0;
    int vtables_named = 0;
    int methods_renamed = 0;
};

ApplyStats apply_recovery(const std::vector<TypeInfoNode> &nodes,
                          const std::vector<std::pair<const TypeInfoNode*, VTableInfo>> &vtables,
                          bool rename_methods) {
    ApplyStats stats;

    for (const auto &[cls, vt] : vtables) {
        std::string vt_name = sanitize_ident(cls->class_name) + "_vtable";
        if (vt.offset_to_top != 0) {
            char suffix[32];
            qsnprintf(suffix, sizeof(suffix), "_at_%lld",
                      static_cast<long long>(vt.offset_to_top));
            vt_name += suffix;
        }

        if (set_name(vt.address, vt_name.c_str(), SN_NOWARN | SN_FORCE | SN_NOCHECK)) {
            stats.vtables_named++;
        }

        if (rename_methods) {
            for (size_t i = 0; i < vt.vfuncs.size(); i++) {
                func_t *f = get_func(vt.vfuncs[i]);
                if (f == nullptr) continue;

                qstring cur;
                get_func_name(&cur, f->start_ea);
                bool is_default_name = (cur.size() > 4
                                       && std::memcmp(cur.c_str(), "sub_", 4) == 0);
                if (!is_default_name) continue;

                char buf[16];
                qsnprintf(buf, sizeof(buf), "%zu", i);
                std::string nm = sanitize_ident(cls->class_name);
                nm += "::vfunc_";
                nm += buf;
                if (set_name(f->start_ea, nm.c_str(), SN_NOWARN | SN_NOCHECK)) {
                    stats.methods_renamed++;
                }
            }
        }
        stats.classes_recovered++;
    }

    (void)nodes;
    return stats;
}

const char *kind_str(TypeInfoKind k) {
    switch (k) {
        case TypeInfoKind::Class:    return "leaf";
        case TypeInfoKind::SiClass:  return "single_inherit";
        case TypeInfoKind::VmiClass: return "multi_or_virtual_inherit";
    }
    return "?";
}

json handle_recover_cpp_classes(const json &params) {
    bool dry_run = params.value("dry_run", false);
    bool rename_methods = params.value("rename_methods", true);

    if (!detect_itanium_abi()) {
        return json{
            {"itanium_abi_detected", false},
            {"note", "No __cxxabiv1 typeinfo vtables found. This binary does not "
                     "use the Itanium C++ ABI (Linux/macOS GCC/Clang). For Windows "
                     "MSVC binaries, install the IDA 'Class Informer' plugin "
                     "(github.com/herosi/classinformer)."},
            {"classes_recovered", 0},
            {"vtables_named", 0},
            {"methods_renamed", 0}
        };
    }

    std::vector<TypeInfoNode> typeinfo_nodes = find_all_typeinfo_nodes();

    std::map<ea_t, const TypeInfoNode*> by_addr;
    std::set<ea_t> ti_addrs;
    for (const auto &n : typeinfo_nodes) {
        by_addr[n.address] = &n;
        ti_addrs.insert(n.address);
    }

    std::vector<std::pair<const TypeInfoNode*, VTableInfo>> all_vtables;
    for (auto &vt : find_vtables_for_typeinfo_set(ti_addrs)) {
        auto it = by_addr.find(vt.typeinfo);
        if (it == by_addr.end()) continue;
        all_vtables.emplace_back(it->second, std::move(vt));
    }

    ApplyStats stats;
    if (dry_run) {
        stats.classes_recovered = (int)typeinfo_nodes.size();
        stats.vtables_named = (int)all_vtables.size();
        for (const auto &p : all_vtables) {
            stats.methods_renamed += (int)p.second.vfuncs.size();
        }
    } else {
        stats = apply_recovery(typeinfo_nodes, all_vtables, rename_methods);
    }

    json sample = json::array();
    for (size_t i = 0; i < typeinfo_nodes.size() && i < 20; i++) {
        const auto &n = typeinfo_nodes[i];
        sample.push_back({
            {"typeinfo_address", format_ea(n.address)},
            {"class_name",       n.class_name.c_str()},
            {"kind",             kind_str(n.kind)},
            {"base_count",       n.bases.size()}
        });
    }

    return json{
        {"itanium_abi_detected", true},
        {"typeinfos_parsed",     typeinfo_nodes.size()},
        {"vtables_found",        all_vtables.size()},
        {"classes_recovered",    stats.classes_recovered},
        {"vtables_named",        stats.vtables_named},
        {"methods_renamed",      stats.methods_renamed},
        {"dry_run",              dry_run},
        {"rename_methods",       rename_methods},
        {"sample_classes",       sample}
    };
}

json handle_list_recovered_vtables(const json &params) {
    if (!detect_itanium_abi()) {
        throw std::runtime_error(
            "Binary does not use Itanium C++ ABI (no __cxxabiv1 typeinfo vtables found).");
    }

    int limit = params.value("limit", 50);
    int offset = params.value("offset", 0);

    auto nodes = find_all_typeinfo_nodes();
    json out = json::array();
    int seen = 0;
    int emitted = 0;

    for (const auto &n : nodes) {
        for (const auto &vt : find_vtables_for_typeinfo(n.address)) {
            if (seen++ < offset) continue;
            if (emitted >= limit) break;

            json vfuncs = json::array();
            for (size_t i = 0; i < vt.vfuncs.size() && i < 64; i++) {
                qstring fname;
                get_func_name(&fname, vt.vfuncs[i]);
                vfuncs.push_back({
                    {"slot",    i},
                    {"address", format_ea(vt.vfuncs[i])},
                    {"name",    fname.c_str()}
                });
            }

            out.push_back({
                {"class_name",       n.class_name.c_str()},
                {"vtable_address",   format_ea(vt.address)},
                {"typeinfo_address", format_ea(n.address)},
                {"offset_to_top",    vt.offset_to_top},
                {"vfunc_count",      vt.vfuncs.size()},
                {"vfuncs",           vfuncs}
            });
            emitted++;
        }
        if (emitted >= limit) break;
    }

    return json{
        {"vtables", out},
        {"limit",   limit},
        {"offset",  offset},
        {"total_typeinfos", nodes.size()}
    };
}

}  // anonymous namespace

void register_tools(mcp::McpServer &server) {
    {
        mcp::ToolDefinition def;
        def.name = "recover_cpp_classes";
        def.description =
            "One-shot Itanium C++ ABI class recovery. Scans the binary for typeinfo "
            "(RTTI) nodes, parses the class hierarchy from __class_type_info / "
            "__si_class_type_info / __vmi_class_type_info structures, names every "
            "vtable as ClassName_vtable, and renames each virtual method as "
            "ClassName::vfunc_N. Run ONCE per binary; subsequent decompile_function "
            "calls automatically resolve `call qword ptr [reg+N]` virtual dispatches "
            "because Hex-Rays uses the recovered names from the IDB. Itanium ABI only "
            "(Linux/macOS GCC/Clang). Windows MSVC binaries need the separate "
            "ClassInformer plugin (github.com/herosi/classinformer).";
        def.input_schema = json{
            {"type", "object"},
            {"properties", {
                {"dry_run",        {{"type", "boolean"}, {"default", false},
                                    {"description", "Scan and report counts WITHOUT modifying the IDB."}}},
                {"rename_methods", {{"type", "boolean"}, {"default", true},
                                    {"description", "Also rename sub_XXXX virtual methods to ClassName::vfunc_N. Disable to only name vtables."}}}
            }}
        };
        server.register_tool(def, handle_recover_cpp_classes);
    }
    {
        mcp::ToolDefinition def;
        def.name = "list_recovered_vtables";
        def.description =
            "List C++ vtables found via Itanium ABI typeinfo scanning. Returns each "
            "vtable's class name, address, offset-to-top, and the resolved vfunc[] "
            "array (slot index + address + name). Read-only; pair with "
            "recover_cpp_classes to first populate names.";
        def.input_schema = json{
            {"type", "object"},
            {"properties", {
                {"limit",  {{"type", "integer"}, {"default", 50}}},
                {"offset", {{"type", "integer"}, {"default", 0}}}
            }}
        };
        server.register_tool(def, handle_list_recovered_vtables);
    }
}

}  // namespace ida_mcp::tools::cpp_class_recovery
