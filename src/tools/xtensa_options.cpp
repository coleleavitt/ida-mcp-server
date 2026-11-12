// MCP tools for configuring IDA's Xtensa processor module at runtime.
//
// IDA's procs/xtensa.so supports many optional Xtensa ISA extensions (Code Density,
// Windowed Register ABI, Loop, MAC16, Boolean, ...) but they are OFF by default.  When
// analysing Intel Wi-Fi firmware (BE200/BE201, AX210, ...), ESP32/ESP8266, or any modern
// Xtensa target, the Code Density extension is mandatory — bytes like `e0 78` are narrow
// L32I.N / S32I.N instructions that IDA otherwise refuses to decode.
//
// These tools:
//   1. `enable_xtensa_feature` — flip a single feature bit in the Xtensa config netnode
//   2. `set_xtensa_features`   — bulk-set the whole feature bitmask
//   3. `get_xtensa_features`   — read the current bitmask with a decoded summary
//
// The bit layout was reverse-engineered from `procs/xtensa.so` in IDA 9.3sp1 by
// decompiling the processor-options dialog (sub_11A90 in the stripped binary).  The
// feature bitmask is stored in a netnode named `$ xtensa options`, persisted via the
// processor module's `ev_set_idp_options` handler.
//
// Bit positions (confirmed from the dialog reverse engineering):
//
//   | Bit   | Mask         | Feature                            |
//   |-------|--------------|------------------------------------|
//   | 2     | 0x00000004   | Other (misc)                       |
//   | 3     | 0x00000008   | **Code Density** (L32I.N etc.)     |
//   | 4     | 0x00000010   | Loop                               |
//   | 6     | 0x00000040   | 16-bit Integer Multiply            |
//   | 7     | 0x00000080   | 32-bit Integer Multiply            |
//   | 8     | 0x00000100   | 32-bit Integer Divide              |
//   | 9     | 0x00000200   | MAC16                              |
//   | 10    | 0x00000400   | Miscellaneous Operations           |
//   | 11    | 0x00000800   | Floating Point 2000                |
//   | 12    | 0x00001000   | Boolean                            |
//   | 13    | 0x00002000   | Memory Protection (variant)        |
//   | 14    | 0x00004000   | Floating Point (newer)             |
//   | 15    | 0x00008000   | Multiprocessor Synchronization     |
//   | 16    | 0x00010000   | Conditional Store                  |
//   | 17    | 0x00020000   | Exclusive Access                   |
//   | 18    | 0x00040000   | Exception                          |
//   | 19    | 0x00080000   | Interrupt                          |
//   | 20    | 0x00100000   | High-Priority Interrupt            |
//   | 21    | 0x00200000   | Memory ECC/Parity                  |
//   | 22    | 0x00400000   | Region Protection                  |
//   | 23    | 0x00800000   | Memory Protection                  |
//   | 24    | 0x01000000   | Windowed Register                  |
//   | 25    | 0x02000000   | Debug                              |
//   | 26    | 0x04000000   | Xtensa Instruction Set Simulator   |
//   | 27    | 0x08000000   | Block Prefetch                     |
//   | 28    | 0x10000000   | Data Cache                         |
//   | 29    | 0x20000000   | Instruction Cache                  |

#include "tools/tools.hpp"

#include <auto.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <netnode.hpp>

#include <array>
#include <cstring>
#include <string_view>

namespace ida_mcp::tools::xtensa_options {
namespace {

// ─────────────────────────────────────────────────────────────────────────────
// Feature catalogue
// ─────────────────────────────────────────────────────────────────────────────

struct FeatureDef {
    std::string_view name;   // canonical lowercase name accepted by the tools
    uint32_t         mask;   // single-bit mask
    std::string_view display; // human label
};

// Forward declaration (used in feature_summary).
static std::string format_hex32(uint32_t v);

// Order matches the bit position for readability, but lookup is by name.
constexpr std::array<FeatureDef, 27> kFeatures = {{
    {"other",              0x00000004, "Other (misc)"},
    {"code_density",       0x00000008, "Code Density"},
    {"loop",               0x00000010, "Loop"},
    {"int_mul16",          0x00000040, "16-bit Integer Multiply"},
    {"int_mul32",          0x00000080, "32-bit Integer Multiply"},
    {"int_div32",          0x00000100, "32-bit Integer Divide"},
    {"mac16",              0x00000200, "MAC16"},
    {"misc_ops",           0x00000400, "Miscellaneous Operations"},
    {"fp2000",             0x00000800, "Floating Point 2000"},
    {"boolean",            0x00001000, "Boolean"},
    {"mem_protection_v2",  0x00002000, "Memory Protection (variant)"},
    {"fp",                 0x00004000, "Floating Point (newer)"},
    {"multiproc_sync",     0x00008000, "Multiprocessor Synchronization"},
    {"cond_store",         0x00010000, "Conditional Store"},
    {"exclusive_access",   0x00020000, "Exclusive Access"},
    {"exception",          0x00040000, "Exception"},
    {"interrupt",          0x00080000, "Interrupt"},
    {"hp_interrupt",       0x00100000, "High-Priority Interrupt"},
    {"mem_ecc_parity",     0x00200000, "Memory ECC/Parity"},
    {"region_protection",  0x00400000, "Region Protection"},
    {"mem_protection",     0x00800000, "Memory Protection"},
    {"windowed",           0x01000000, "Windowed Register"},
    {"debug",              0x02000000, "Debug"},
    {"simulator",          0x04000000, "Xtensa Instruction Set Simulator"},
    {"block_prefetch",     0x08000000, "Block Prefetch"},
    {"data_cache",         0x10000000, "Data Cache"},
    {"instruction_cache",  0x20000000, "Instruction Cache"},
}};

// Recommended bundle for modern (Wi-Fi 7 BE200/BE201, ESP32-S3, etc.) firmware.
constexpr uint32_t kWiFiPreset =
    0x00000008 | // code_density
    0x00000010 | // loop
    0x00000040 | // int_mul16
    0x00000080 | // int_mul32
    0x00000200 | // mac16
    0x00000400 | // misc_ops
    0x00001000 | // boolean
    0x00040000 | // exception
    0x00080000 | // interrupt
    0x00100000 | // hp_interrupt
    0x01000000 | // windowed
    0x02000000;  // debug

constexpr const char   kXtensaNetnodeName[] = "$ xtensa options";
constexpr nodeidx_t    kFeatureAltvalIdx    = 0;  // feature mask is altval[0] per sub_11980 RE

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

bool is_xtensa_database() {
    char name[64] = {};
    get_idp_name(name, sizeof(name));
    return std::string_view{name} == "xtensa";
}

const FeatureDef *lookup_feature(std::string_view name) {
    for (const auto &f : kFeatures) {
        if (f.name == name) return &f;
    }
    return nullptr;
}

json feature_summary(uint32_t flags) {
    json enabled  = json::array();
    json disabled = json::array();
    for (const auto &f : kFeatures) {
        json entry = {
            {"name", std::string(f.name)},
            {"mask", f.mask},
            {"display", std::string(f.display)},
        };
        if (flags & f.mask) enabled.push_back(entry);
        else                disabled.push_back(entry);
    }
    return json{
        {"flags_hex", format_hex32(flags)},
        {"flags",     flags},
        {"enabled",   enabled},
        {"disabled",  disabled},
    };
}

static std::string format_hex32(uint32_t v) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "0x%08x", v);
    return buf;
}

// Read the current feature bitmask. Xtensa's sub_11980 uses netnode_altval() to read;
// altval returns 0 when the slot is unset, which the module interprets as "use defaults".
uint32_t read_feature_mask() {
    netnode nn(kXtensaNetnodeName);
    if (!exist(nn)) return 0;
    return static_cast<uint32_t>(nn.altval(kFeatureAltvalIdx));
}

// Write a new feature bitmask via altset (matching the writer in sub_117E0 was supset, but
// the reader uses altval — so we write BOTH to survive both code paths).
void write_feature_mask(uint32_t value) {
    netnode nn;
    nn.create(kXtensaNetnodeName);
    nn.altset(kFeatureAltvalIdx, value);
    nn.supset(kFeatureAltvalIdx, &value, sizeof(value));
}

// Queue re-analysis of every code segment with the new Xtensa feature flags
// applied. Does NOT call auto_wait() - that would block IDA's main thread for
// minutes on large firmware images, freezing the UI and timing out HTTP clients.
// Callers can poll via the `auto_wait` MCP tool if they need to wait for
// completion before issuing follow-up decoding queries.
void reanalyse_all_code_segments() {
    set_processor_type("xtensa", SETPROC_LOADER_NON_FATAL);

    for (segment_t *s = get_first_seg(); s != nullptr; s = get_next_seg(s->start_ea)) {
        if (s->type == SEG_CODE || (s->perm & SEGPERM_EXEC)) {
            plan_range(s->start_ea, s->end_ea);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool handlers
// ─────────────────────────────────────────────────────────────────────────────

json handle_get_xtensa_features(const json &) {
    uint32_t flags = read_feature_mask();
    json out = feature_summary(flags);
    out["processor"]      = is_xtensa_database() ? "xtensa" : "NOT xtensa (call has no effect)";
    out["netnode"]        = kXtensaNetnodeName;
    out["altval_index"]   = kFeatureAltvalIdx;
    return out;
}

json handle_enable_xtensa_feature(const json &params) {
    std::string name = params.value("feature", "code_density");
    bool enable = params.value("enable", true);
    bool reanalyse = params.value("reanalyse", true);

    const FeatureDef *feat = lookup_feature(name);
    if (!feat) {
        json known = json::array();
        for (const auto &f : kFeatures) known.push_back(std::string(f.name));
        throw std::runtime_error(
            "Unknown feature '" + name + "'. Known: " + known.dump()
        );
    }

    if (!is_xtensa_database()) {
        return json{
            {"success", false},
            {"error", "current database processor is not 'xtensa'"},
            {"hint", "load the firmware ELF first, then call this tool"},
        };
    }

    uint32_t before = read_feature_mask();
    uint32_t after  = enable ? (before | feat->mask) : (before & ~feat->mask);
    write_feature_mask(after);

    if (reanalyse && before != after) reanalyse_all_code_segments();

    return json{
        {"success", true},
        {"feature", std::string(feat->name)},
        {"display", std::string(feat->display)},
        {"mask", format_hex32(feat->mask)},
        {"enabled", enable},
        {"flags_before", format_hex32(before)},
        {"flags_after",  format_hex32(after)},
        {"reanalysed", reanalyse && before != after},
    };
}

json handle_set_xtensa_features(const json &params) {
    if (!is_xtensa_database()) {
        return json{
            {"success", false},
            {"error", "current database processor is not 'xtensa'"},
        };
    }

    uint32_t flags = 0;
    if (params.contains("preset")) {
        std::string preset = params["preset"].get<std::string>();
        if (preset == "wifi" || preset == "be200" || preset == "esp32") {
            flags = kWiFiPreset;
        } else if (preset == "none") {
            flags = 0;
        } else {
            throw std::runtime_error("unknown preset: " + preset);
        }
    } else if (params.contains("flags_hex")) {
        std::string h = params["flags_hex"].get<std::string>();
        flags = static_cast<uint32_t>(std::stoul(h, nullptr, 0));
    } else if (params.contains("features") && params["features"].is_array()) {
        for (auto &e : params["features"]) {
            const FeatureDef *f = lookup_feature(e.get<std::string>());
            if (!f) throw std::runtime_error("unknown feature: " + e.get<std::string>());
            flags |= f->mask;
        }
    } else {
        throw std::runtime_error(
            "provide one of: preset='wifi'|'esp32'|'none', flags_hex='0x...', or features=[...]"
        );
    }

    uint32_t before = read_feature_mask();
    write_feature_mask(flags);

    if (params.value("reanalyse", true) && before != flags) {
        reanalyse_all_code_segments();
    }

    json out = feature_summary(flags);
    out["success"]       = true;
    out["flags_before"]  = format_hex32(before);
    out["flags_after"]   = format_hex32(flags);
    out["reanalysed"]    = params.value("reanalyse", true) && before != flags;
    return out;
}

} // anonymous namespace

// ─────────────────────────────────────────────────────────────────────────────
// Registration
// ─────────────────────────────────────────────────────────────────────────────

void register_tools(mcp::McpServer &server) {
    {
        mcp::ToolDefinition def;
        def.name = "get_xtensa_features";
        def.description =
            "Read the current Xtensa processor feature bitmask from the '$ xtensa options' "
            "netnode and return a summary of which optional ISA extensions are enabled "
            "(Code Density, Windowed, MAC16, Boolean, etc).";
        def.input_schema = json{
            {"type", "object"},
            {"properties", json::object()},
        };
        server.register_tool(def, handle_get_xtensa_features);
    }

    {
        mcp::ToolDefinition def;
        def.name = "enable_xtensa_feature";
        def.description =
            "Enable (or disable) a single Xtensa ISA extension by flipping the corresponding "
            "bit in the '$ xtensa options' netnode, then re-analysing the database. "
            "Use feature='code_density' to make L32I.N / S32I.N / MOV.N / ADD.N decodable "
            "for Wi-Fi 7 BE200/BE201, ESP32, and other modern Xtensa targets.";
        def.input_schema = json{
            {"type", "object"},
            {"properties", {
                {"feature",   {{"type", "string"}, {"description",
                    "Feature name: code_density, windowed, loop, mac16, boolean, "
                    "debug, exception, interrupt, hp_interrupt, int_mul32, ..."}}},
                {"enable",    {{"type", "boolean"}, {"default", true},
                               {"description", "Set to false to disable instead of enable"}}},
                {"reanalyse", {{"type", "boolean"}, {"default", true},
                               {"description", "Re-plan analysis on all code segments after changing"}}},
            }},
            {"required", json::array({"feature"})},
        };
        server.register_tool(def, handle_enable_xtensa_feature);
    }

    {
        mcp::ToolDefinition def;
        def.name = "set_xtensa_features";
        def.description =
            "Bulk-set the Xtensa feature bitmask, overwriting all current settings. "
            "Accepts a preset ('wifi' for Intel Wi-Fi 7 firmware, 'esp32' for ESP32/ESP8266, "
            "'none' to clear), a raw hex mask, or a list of feature names.";
        def.input_schema = json{
            {"type", "object"},
            {"properties", {
                {"preset",    {{"type", "string"}, {"enum", json::array({"wifi", "be200", "esp32", "none"})}}},
                {"flags_hex", {{"type", "string"}, {"description", "e.g. '0x0305047c'"}}},
                {"features",  {{"type", "array"}, {"items", {{"type", "string"}}},
                               {"description", "List of feature names to enable (all others disabled)"}}},
                {"reanalyse", {{"type", "boolean"}, {"default", true}}},
            }},
        };
        server.register_tool(def, handle_set_xtensa_features);
    }
}

} // namespace ida_mcp::tools::xtensa_options
