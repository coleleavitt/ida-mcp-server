#pragma once

// Standard C++ headers FIRST (before IDA SDK)
#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <functional>
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
