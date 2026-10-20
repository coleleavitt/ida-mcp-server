#pragma once

// Standard C++ headers FIRST (before IDA SDK)
#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <functional>
#include <regex>
#include <cerrno>   // For errno
#include <climits>  // For ULLONG_MAX
// IDA SDK headers (following idacli.cpp pattern)
#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <segment.hpp>
#include <funcs.hpp>
#include <xref.hpp>
#include <name.hpp>
#include <auto.hpp>
#include <search.hpp>
#include <typeinf.hpp>
#include <strlist.hpp>
#include <lines.hpp>
#include <ua.hpp>
#include <idalib.hpp>

// Hexrays decompiler (optional - check license at runtime)
#ifdef HAS_HEXRAYS
#include <hexrays.hpp>
#endif

// Undefine IDA SDK macros that conflict with external libraries
// This is necessary for nlohmann/json and Boost
#ifdef snprintf
#undef snprintf
#endif
#ifdef sprintf
#undef sprintf
#endif
#ifdef fgetc
#undef fgetc
#endif
#ifdef fopen
#undef fopen
#endif
#ifdef fclose
#undef fclose
#endif
#ifdef ftell
#undef ftell
#endif
#ifdef fseek
#undef fseek
#endif
#ifdef fread
#undef fread
#endif
#ifdef fwrite
#undef fwrite
#endif
#ifdef getenv
#undef getenv
#endif

// Now safe to include external libraries
#include <nlohmann/json.hpp>
#include <boost/asio.hpp>
#include <boost/beast.hpp>

// Type aliases
using json = nlohmann::json;
namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;

// Common utilities
namespace ida_mcp {

// Format ea_t as hex string
inline std::string format_ea(ea_t addr) {
    char buf[32];
    qsnprintf(buf, sizeof(buf), "0x%llX", (uint64)addr);
    return buf;
}

// Parse hex address from string
inline std::optional<ea_t> parse_ea(const std::string& addr_str) {
    const char* str = addr_str.c_str();
    // Skip 0x prefix if present
    if (addr_str.size() > 2 && addr_str[0] == '0' && (addr_str[1] == 'x' || addr_str[1] == 'X')) {
        str += 2;
    }

    char* end;
    errno = 0;  // Reset errno before call
    uint64 addr = strtoull(str, &end, 16);
    // Check for conversion errors: no digits consumed, trailing chars, or overflow
    if (end == str || *end != '\0' || (errno == ERANGE && addr == ULLONG_MAX)) {
        return std::nullopt;
    }
    return addr;
}

// Get function name with fallback to auto-generated name
inline std::string get_function_name(func_t* func) {
    if (!func) return "";

    qstring name;
    if (get_func_name(&name, func->start_ea) > 0) {
        return name.c_str();
    }

    char buf[32];
    qsnprintf(buf, sizeof(buf), "sub_%llX", (uint64)func->start_ea);
    return buf;
}

// Get segment name
inline std::string get_segment_name(ea_t addr) {
    segment_t* seg = getseg(addr);
    if (!seg) return "";

    qstring name;
    get_visible_segm_name(&name, seg);
    return name.c_str();
}

// Check if address is valid
inline bool is_valid_ea(ea_t addr) {
    return is_loaded(addr);
}

// Detect Go-compiler-generated pathological symbols that hang Hex-Rays calc_arglocs.
//
// IDA 9.3sp1 partially fixed this (release notes: "golang: fixed infinite loop when
// processing structs with self-referential pointer cycles") but the fix covers only
// STRUCT cycles. Go's type system uses @N backreference notation for cycles in shape
// names (e.g. `go.shape.interface { M() @0 }`), but IDA's golang.so / idaclang.so
// plugins don't understand backreferences and re-expand them → O(2^N) / infinite
// recursion in libida's type resolver.
//
// Symbol prefixes sourced from Go compiler source (go/src/cmd/compile/internal/):
//   go.shape.*          shape types for generics (types/type.go:1988, noder/reader.go:947)
//   go:itab.*           interface method tables (reflectdata/reflect.go:602) — NOTE: colon not dot
//   go:info.*           DWARF type DIEs (cmd/internal/dwarf/dwarf.go:24)
//   go:constinfo.*      DWARF const info (dwarf.go:28)
//   go:cuinfo.*         compilation unit info (dwarf.go:32)
//   type..*             type descriptors (types/type.go:1958)
//   type..noalg.*       types without hash/eq (types/type.go:1969)
//   type:.importpath.*  import path metadata (reflectdata/reflect.go:1383)
//   type:.gcmask.*      GC bitmasks (reflectdata/reflect.go:1313)
//   .dict.*             generic dictionaries (objabi/util.go:17)
//   .inst.*             generic instantiations (reflectdata/reflect.go:1404)
//   .hashfunc.*         compiler-generated hash closures (reflectdata/alg.go:60)
//   .eqfunc.*           compiler-generated equality closures (reflectdata/alg.go:296)
//   .autotmp_*          compiler temporaries (typecheck/dcl.go:95)
//
// Two checks, cheap-to-expensive:
//   1. Name regex — catches all compiler-generated prefixes above
//   2. Cached tinfo string — catches user functions whose prototypes REFERENCE shape types
//
// THREAD-SAFETY: Must be called from IDA's main thread (get_tinfo / tinfo_t::print).
inline bool is_go_pathological_func(func_t* func, std::string* reason = nullptr) {
    if (!func) return false;

    qstring fname;
    if (get_func_name(&fname, func->start_ea) <= 0) return false;

    // Covers: go.shape.*, go:itab.*, go:info.*, go:constinfo.*, go:cuinfo.*,
    //         go:string.*, go:track.*, go:func.*, go:map.*,
    //         type..*, type..noalg.*, type:.importpath.*, type:.gcmask.*,
    //         .dict.*, .inst.*, .hashfunc.*, .eqfunc.*, .hash.*, .eq.*,
    //         .gcmask.*, .autotmp_*
    static const std::regex go_generated{
        R"((?:^|[._])go[.:](?:shape|itab|info|constinfo|cuinfo|string|track|func|map|builtin|plugin)\.)"
        R"(|^type[.:]\.)"
        R"(|^\.(?:dict|inst|hashfunc|eqfunc|hash|eq|gcmask)\.)"
        R"(|^\.autotmp_)"};
    if (std::regex_search(fname.c_str(), go_generated)) {
        if (reason) *reason = std::string("Go compiler-generated symbol: ") + fname.c_str();
        return true;
    }

    tinfo_t tif;
    if (get_tinfo(&tif, func->start_ea)) {
        qstring tstr;
        tif.print(&tstr);
        if (tstr.find("go.shape.") != qstring::npos
            || tstr.find("go:itab.") != qstring::npos
            || tstr.find("go:info.") != qstring::npos) {
            if (reason) *reason = std::string("signature references Go shape/itab/info type: ") + tstr.c_str();
            return true;
        }

        constexpr int kMaxGenericDepth = 8;
        int depth = 0;
        int max_depth = 0;
        for (size_t i = 0; i < tstr.size(); ++i) {
            char c = tstr[i];
            if (c == '<') { ++depth; if (depth > max_depth) max_depth = depth; }
            else if (c == '>') --depth;
        }
        if (max_depth >= kMaxGenericDepth) {
            if (reason) {
                char buf[64];
                qsnprintf(buf, sizeof(buf), "%d", max_depth);
                *reason = std::string("type signature has ") + buf
                       + " levels of nested generics (Hex-Rays mop_t::for_all_ops "
                         "infinite recursion risk - sub_127FE0): " + tstr.c_str();
            }
            return true;
        }
    }

    constexpr int kMaxRustGenericMarkers = 8;
    int rust_markers = 0;
    {
        std::string_view sv(fname.c_str(), fname.size());
        size_t pos = 0;
        while ((pos = sv.find("_LT_", pos)) != std::string_view::npos) {
            ++rust_markers;
            pos += 4;
            if (rust_markers >= kMaxRustGenericMarkers) break;
        }
    }
    if (rust_markers >= kMaxRustGenericMarkers) {
        if (reason) {
            char buf[64];
            qsnprintf(buf, sizeof(buf), "%d", rust_markers);
            *reason = std::string("Rust mangled name has ") + buf
                   + " generic-instantiation markers (Hex-Rays mop_t recursion risk): "
                   + fname.c_str();
        }
        return true;
    }

    constexpr asize_t kMaxSafeFuncSize = 16 * 1024;
    asize_t fsz = func->size();
    if (fsz > kMaxSafeFuncSize) {
        if (reason) {
            char buf[128];
            qsnprintf(buf, sizeof(buf),
                      "function size %llu bytes exceeds %llu KB safe-decompile threshold "
                      "(stock MAX_FUNCSIZE was 64 KB; we patched it out, but Hex-Rays "
                      "mop_t::for_all_ops infinite-loops on huge SIMD/vectorized functions - "
                      "Crashpad CaptureContext, video codec SAD loops, etc.)",
                      (unsigned long long)fsz,
                      (unsigned long long)(kMaxSafeFuncSize / 1024));
            *reason = buf;
        }
        return true;
    }

    return false;
}

// Execute function on IDA's main thread (required for all IDA API calls)
template<typename F>
inline auto execute_on_main_thread(F&& func) -> decltype(func()) {
    using ReturnType = decltype(func());
    
    struct SyncRequest : public exec_request_t {
        F& func;
        ReturnType* result_ptr;
        std::exception_ptr exception;
        
        SyncRequest(F& f, ReturnType* r) : func(f), result_ptr(r) {}
        
        ssize_t idaapi execute() override {
            try {
                if constexpr (std::is_void_v<ReturnType>) {
                    func();
                } else {
                    *result_ptr = func();
                }
            } catch (...) {
                exception = std::current_exception();
            }
            return 0;
        }
    };
    
    if constexpr (std::is_void_v<ReturnType>) {
        SyncRequest req(func, nullptr);
        execute_sync(req, MFF_WRITE);
        if (req.exception) std::rethrow_exception(req.exception);
    } else {
        ReturnType result{};
        SyncRequest req(func, &result);
        execute_sync(req, MFF_WRITE);
        if (req.exception) std::rethrow_exception(req.exception);
        return result;
    }
}

} // namespace ida_mcp
