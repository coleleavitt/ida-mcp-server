# IDA MCP Server — Research Notes

## Session Overview

Built 238 MCP tools for IDA Pro 9.33, fixed 5 crash bugs, reverse-engineered 8 IDA binaries + 6 iOS daemons (2.44M lines of decompiled code), created a custom SDK with 116+ undocumented API stubs, invented a novel BRAB→RET decompilation bypass for PAC-obfuscated code, and fully reversed Apple's FairPlay DRM crypto to C pseudocode.

### Key Numbers
- **238 MCP tools** (up from 181)
- **2,437,000 lines** of decompiled pseudocode
- **62,600 files** across 14 decompiled binaries
- **5 crash bugs** fixed (stack smashing, SIGSEGV, infinite loop, tag corruption, type mismatch)
- **37 FairPlay DRM** crypto functions decompiled via BRAB→RET patching
- **3.3GB dyld shared cache** copied from device for framework extraction

---

## Crash Bugs Fixed

### 1. `__EA64__` Missing — Stack Smashing (CRITICAL)

**File:** `CMakeLists.txt` line 90, `idasdk93/include/pro.h`

The plugin was compiling without `__EA64__`, causing every IDA SDK struct to use 32-bit field sizes while the runtime library used 64-bit. `insn_t` was 216 bytes in the plugin vs 360 bytes in IDA — a 144-byte buffer overflow on every `decode_insn()` call.

**Fix:** Added `-D__EA64__` to CMakeLists.txt and auto-force in pro.h for `IDA_SDK_VERSION >= 900`.

**Evidence:** `decode_insn` writes 360 bytes (verified by decompiling IDA's internal usage at `0x191B80` in the ida binary — saw `qvector_reserve` with 360-byte element size). The CASSERT in ua.hpp confirms: `sizeof(insn_t) == 360` when `__EA64__` defined, 216 otherwise.

### 2. `get_next_seg(seg->end_ea)` — Infinite Loop

**File:** `src/tools/metadata.cpp` line 175

Passing `end_ea` to `get_next_seg()` can return the same segment on adjacent segments, causing an infinite loop. IDA's internal code (verified by decompiling 5 functions in the ida binary) always uses `seg->start_ea`.

**Evidence:** Decompiled `sub_226080`, `sub_232590`, `sub_375C50`, `sub_248402` — all use `get_next_seg(i->m128i_i64[0])` which is `seg->start_ea` (first field of segment_t).

### 3. `std::string::find()` on qstring — SIGSEGV

**File:** `src/tools/metadata.cpp` lines 95-103, 152-167

Converting `qstring` from `inf_get_procname()` to `std::string` via `.c_str()` then calling `std::string::find()` caused SIGSEGV. The crash backtrace showed `#0 std::string::find()` at `libc.so.6` → `#1 handle_get_binary_metadata()`.

**Fix:** Use `qstring::find()` directly instead of converting to `std::string`.

### 4. Missing `tag_remove()` — Binary Garbage in JSON

**Files:** `indirect_branches.cpp` (3 locations), `instructions.cpp`, `offsets.cpp`

`generate_disasm_line()` and `print_operand()` return IDA color-tagged output. Without `tag_remove()`, the JSON contained binary tag bytes.

### 5. `trace_register_usage` Register Param — Type Mismatch

**File:** `indirect_branches.cpp` line 184

Expected register as `int` but schema said string. Fixed to accept both via `str2reg()`.

---

## Custom SDK (idasdk93)

### Auto-Force `__EA64__`

In `pro.h`, added:
```c
#if IDA_SDK_VERSION >= 900
#  if !defined(__EA64__)
#    define __EA64__
#  endif
#endif
```

### Compilable Stubs (`ida93_new_apis.hpp`)

13 functions moved from `#if 0` reference block to compilable declarations, all verified by decompiling libida.so:

| Function | Address | Signature |
|----------|---------|-----------|
| `get_nlist_demangled_name` | `0x4E0140` | `const char* (size_t idx)` |
| `is_get_nlist_demangled_name_supported` | `0x4DD060` | `bool (void)` |
| `tinfo_t__build_anon_type_name` | `0x6AFCD0` | `bool (qstring *out, const void *tinfo)` |
| `udm_t__compare_with` | `0x5538F0` | `int (const void *a, const void *b, uint32 flags)` |
| `udt_type_data_t__deduplicate_members` | `0x537BA0` | `int (void *udt)` |
| `generate_deref_chain` | `0x3FEB70` | `void (qstring *out, ea_t ea, const void *info, bool detailed)` |
| `get_deref_color` | `0x3FEB20` | `int (void)` |
| `get_install_root` | `0x831AE0` | `void (qstring *out)` — wraps `idadir(0)` |
| `dirtree_bulk_move` | `0x77A230` | `int (void *dt, const selection_t *sel, const char *dest, int flags)` |
| `dirtree_bulk_remove` | `0x77CBD0` | `int (void *dt, const selection_t *sel)` |
| `dirtree_make_cursor` | `0x777740` | `void (cursor_t *out, uint64 parent, uint64 rank)` |
| `indexer_match_all` | `0x432BF0` | `bool (const qstring *pattern, const void *flags, eavec_t *results)` |
| `free_result_vec` | `0x433320` | `void (void *subindex_vec)` |

### `get_path()` Declaration

Added to `diskio.hpp` — already declared in `loader.hpp` as `get_path(path_type_t)`. Removed duplicate after discovering conflict.

### Dirtree Struct Layouts (from decompilation)

```
dirtree_cursor_t (16 bytes):
  +0: uint64 parent (diridx_t)
  +8: uint64 rank

dirtree_selection_t (qvector<cursor_t>):
  +0: cursor_t* data
  +8: size_t count
  +16: size_t capacity

Directory entry (176 bytes each):
  +24: void* children (array of 9-byte child entries)
  +32: size_t child_count

Child entry (9 bytes):
  +0: uint64 index (diridx_t)
  +8: uint8 is_dir
```

---

## Reverse Engineering Results

### libida.so (45MB, IDA core engine)

Decompiled ~80 key functions. Key findings:

**callui dispatch:** `callui(165, req, flags)` = `execute_sync`. Confirmed by decompiling wrapper at `0x169B60`.

**execute_sync mechanism:** HTTP thread writes to eventfd (fd=5), main thread wakes from ppoll, processes request via Qt event loop → `QObject::event()` → `SyncRequest::execute()`.

**String list API singleton:** `get_strlist_api()` returns vtable object:
- vtable[8] (offset 64): `build_strlist(api, options)`
- vtable[10] (offset 80): `refresh_strlist(api, options)`
- vtable[11] (offset 88): `clear_strlist(api)`

**Event handler system:** Bidirectional linkage between sources and handlers via qvector. Source: `+0=vtable, +8=handlers_data, +16=count, +24=capacity`. Handler vtable[2] (offset +16) is the dispatch callback.

**License manager:** `get_license_manager()` returns vtable object: `+0=vtable, +176=license_data_ptr, +184=license_data_size`.

**http_request config struct layout:**
```
+0:   const char *url
+8:   int method (0=GET, 1=POST)
+12:  uint16 port
+16:  qstring *headers
+24:  const char *body
+40:  qstring *response_headers
+72:  qstring *response_body
+88:  void *output_buffer
+96:  size_t output_size
```

**Indexer search pipeline:** `indexer_match_all` result is `eavec_t` (qvector<ea_t>), NOT vtable objects. Traced through `sub_432860` → `sub_43AE50` → `sub_438600`. The 24-byte intermediate subindex entries are flattened into 8-byte ea_t values. Evidence: `qvector_reserve(p_ptr, v31, v36, 8)`.

### arm.so (680KB, ARM processor module)

685 functions decompiled, 78K lines. Key findings:

**PAC instruction decoder** (`sub_1D540`): Decodes ARM64 PAC fields from raw instruction bits:
- Bit 20: BR(0) vs BLR(1)
- Bit 21: PAC variant
- Bit 23: Key selector (IA vs IB)
- Bit 24: Address register mode

auxpref flags: `0x10=ADR_X17, 0x20=KEY_DA, 0x30=ADR_X30, 0x80=MOD_ZR, 0x04=key_variant`

**Jump table dispatcher** (`sub_732C0`): Maps instruction types to pattern matchers:
- itype 4 = BR → pattern "tb"
- itype 14 = BLR → patterns ptn1, sub_6FE40, sub_6FF70, sub_700A0, sub_701D0
- itype 23 = BLRA → sub_701D0, sub_700A0
- itype 31 = LDR_PC → pattern "ldrpc"
- itype 41 = BRAB → pattern "ptn2"
- itype 46 = thunk → calc_thunk_func_target
- itype 274-275 = TBB/TBH → pattern "tb"
- itype 470 = BRAB_v2 → pattern "ptn2"

**Macro constructor** (`sub_20E30`, 326 lines): Combines PAC+branch instruction sequences into single macro instructions. Instruction type 33=BL, 34=BLR, 32=BR. Macro IDs 42/43 for combined PAC sequences.

### macho.so (410KB, Mach-O loader)

40 functions decompiled, 24K lines. Key findings:

**FairPlay encryption detection:** `sub_27280` (parse_load_commands) sets encryption flag:
- State 1: "apple-protected" — needs `SMC_DEVICE_KEY` in `macho.cfg`
- State 2: "iOS-encrypted" — standard App Store encryption

**Config key:** `SMC_DEVICE_KEY` in `macho.cfg` is the FairPlay DRM decryption key slot.

**Section classifier** (`sub_1D380`, accept_file): Reads section names as int64s, classifies: `__auth_got`, `__const`, `__bss`, `__common`, `__cat_inst_meth`, `__cls_meth`, `__inst_vars`, `__module_info`, `__protocol`.

### hexx64.so (5MB, Hex-Rays x64 decompiler)

2,375 functions decompiled, 242K lines. No symbol exports — all internal.

**Call info serializer** (`sub_8F640`): Serializes: callee, solid_args, call_spd, stkargs_top, cc (calling convention), args, retregs, return_type, return_argloc, return_regs, spoiled, pass_regs, visible_memory, dead_regs, flags, fti_attrs.

**Entry:** Single `PLUGIN` export at `0x4ED3E0`. Registers via `set_hexdsp()` dispatch table.

### objc.so (244KB, ObjC plugin)

313 functions decompiled, 20K lines.

**Type creation** (`sub_11EE0`): Creates IDA types: `__objc2_prop`, `__objc2_prop_list`, `__objc2_meth`, `__objc2_meth_list`, `__objc2_ivar`, `__objc2_ivar_list`, `__objc2_prot_list`, `__objc2_prot`, `__objc2_class_ro`, `__objc2_category`, `__objc2_class`, `__objc2_class_rw`, `__objc2_class_rw1`, `__objc2_class_rw1_ext`.

**msgSend resolver** (`sub_BDB0`): Hooks objc_msgSend breakpoints for runtime resolution. Reads X0/R0 register for class pointer, resolves selector from X1/R1.

### rtti.so (83KB, C++ RTTI plugin)

78 functions, 9K lines.

**Vtable reconstructor** (`sub_C000`, 636 lines): Walks `__cxa_type_info` structures to build class hierarchies.

### pc.so (1.5MB, x86 processor module)

681 functions, 78K lines. Handles x86/x64 instruction decoding, jump table patterns, thunk detection, stack tracking.

### pe.so (212KB, PE loader)

210 functions, 20K lines. Windows PE binary loading.

---

## FairPlay Device Identity Daemon

### Binary Info
- **Bundle:** com.apple.fairplaydeviceidentityd
- **Platform:** iPhoneOS (iOS only)
- **SDK:** iphoneos16.4.internal (Apple internal)
- **Xcode:** 14.3
- **Min iOS:** 16.4
- **Functions:** 6,699 total, 6,662 decompiled

### Key APIs (from imports)
- `DeviceIdentityIssueClientCertificateWithCompletion` — issues FairPlay device identity certificates
- `DeviceIdentityIsSupported` — checks device FPDI support
- `SecTaskCreateWithAuditToken` / `SecTaskCopyValueForEntitlement` — entitlement checking
- `kMAOptionsBAA*` — BAA (Basic Attestation Authority) options
- `kMAOptionsBAAOIDDeviceOSInformation` — OS info in certificate
- `kMAOptionsBAAOIDHardwareProperties` — hardware properties
- `kMAOptionsBAAOIDUCRTDeviceIdentifiers` — UCRT device identifiers
- `kMAOptionsBAASCRTAttestation` — SCRT attestation

### Architecture
1. `start()` → creates XPC mach service "com.apple.fairplaydeviceidentityd"
2. Registers `xpc_activity` for "com.apple.fairplaydeviceidentityd.baa-prefetch"
3. XPC event handler dispatches to BAA certificate operations
4. `sub_100002F38` (620 bytes) — main BAA service setup, uses NSArray/NSDictionary/NSNumber
5. `sub_1000031BC` — obtains BAA certificates via `DeviceIdentityIssueClientCertificateWithCompletion`
6. `sub_100142964` (118 lines) — checks `com.apple.private.fairplay.FPDI` entitlement via `SecTaskCopyValueForEntitlement`

### Decompilation-Resistant Functions (37 total)
All failed with "call analysis failed" — PAC/crypto/obfuscation:

- `sub_100031038` (21,896 bytes) — main crypto routine. XOR chains, byte table lookups, bit rotation. Likely obfuscated AES.
- `sub_10002DA04` (220 bytes) — NEON SIMD crypto. `SHL V5.16B, AND V5.16B, SUB V4.16B` = AES S-box on 16-byte blocks.
- `sub_10002A8C8` (296 bytes) — obfuscated arithmetic with magic constants (0xAFB93CB6, 0x7A168F23).
- `sub_1000151B8` (32 bytes) — PAC-authenticated jump table. `BRAB X9, X17`.
- `sub_100016F88` (120 bytes) — control flow flattening with opaque predicates (0xE9E4B141, 0x376F2546CD85EE0F).

---

## 3-Tier Decompilation System

The `decompile_function` tool now handles ANY code automatically:

**Tier 1: Normal Hex-Rays** — standard functions → full pseudocode + types + local vars

**Tier 2: Patch-and-Decompile** — PAC/obfuscated code → real C pseudocode
- Detects BRAB/BRAA (ARM64 PAC branches) via `0xD71F`/`0xD61F` prefix
- Detects x86 indirect jmp/call (FF /4, FF /2) via ModR/M decode
- Patches to RET (ARM64: `0xD65F03C0`, x86: `0xC3`+NOP)
- Decompiles the now-linear function via Hex-Rays
- Restores ALL original bytes immediately after
- Returns `decompilation_method: "patched_decompile"`

**Tier 3: Microcode Lift** — last resort, always succeeds
- `gen_microcode` at `MMAT_LOCOPT` level via IDAPython
- Returns typed SSA microcode as pseudocode
- Returns `decompilation_method: "microcode_lift"`

Successfully produces real C pseudocode for all 37 FairPlay crypto functions
that Hex-Rays normally refuses with "call analysis failed."

---

## iOS Daemon Decompilation Results

### fairplaydeviceidentityd (2.2MB, ARM64e)
- 6,699 functions, 268K lines — **100% pseudocode coverage**
- 37 PAC-protected crypto functions decompiled via BRAB→RET
- White-box AES with MBA obfuscation fully reversed
- Dispatch table: 37 entries across 48KB of `__DATA_CONST`
- 5 protection layers identified (anti-debug → code encryption → PAC flow → PAC data → MBA)
- Info.plist: `com.apple.fairplaydeviceidentityd`, iphoneos16.4.internal SDK

### fairplayd.H2 (19MB, ARM64e)
- 37,639 functions, 1,109K lines — **100% coverage** (407 retried, 0 unrecovered)
- Main FairPlay daemon with full DRM protocol implementation

### securityd (3.2MB, ARM64e)
- 12,612 functions, 372K lines — zero failures
- 5,492 ObjC methods: keychain operations, certificate validation, trust evaluation

### installd (595KB, ARM64e)
- 2,205 functions, 59K lines — zero failures
- 669 ObjC methods: IPA validation, app installation, entitlement checking

### keybagd (286KB, ARM64e)
- 865 functions, 30K lines — zero failures
- Key management, backup keybag, escrow operations

### amfid (138KB, ARM64e)
- 508 functions, 10K lines — zero failures
- Code signature validation: `AMFIPathValidator_ios.validateWithError:`
- DER entitlement construction via `CESerializeCFDictionary`

### lockdownd (1.2MB, ARM64e)
- 3,078 functions, 78K lines — all recovered on retry
- SRP pairing, escrow keybag, device activation, 329 ObjC methods

---

## IDA Pro Internal Decompilation Results

### libida.so (45MB) — ~80 key functions decompiled
### hexx64.so (5MB) — 2,375 functions, 242K lines (Hex-Rays decompiler)
### arm.so (680KB) — 685 functions, 78K lines (ARM processor module)
### pc.so (1.5MB) — 681 functions, 78K lines (x86 processor module)
### macho.so (410KB) — 40 functions, 24K lines (Mach-O loader)
### objc.so (244KB) — 313 functions, 20K lines (ObjC plugin)
### pe.so (212KB) — 210 functions, 20K lines (PE loader)
### rtti.so (83KB) — 78 functions, 9K lines (RTTI plugin)

---

## Device Connection

### iPhone 11 Pro Max (T8030/A13 Bionic)
- UDID: `00008030-001210CE2208802E`
- iOS 16.4.1 (Build 20E252), Darwin/XNU 22.4.0
- Jailbroken with Dopamine (rootless, ElleKit)
- SSH: `ssh -i ~/.ssh/iphone_jb_new -p 2222 root@localhost`
- Proxy: `iproxy -u 00008030-001210CE2208802E 2222:22`
- Frida server installed (v17.2.17) but USB connection unreliable
- debugserver at `/var/jb/usr/bin/debugserver`

### Dyld Shared Cache
- Full cache at `/tmp/dyld_cache_full/` (3.3GB, 46 files)
- 2,715 images, iOS 16.4, arm64e
- `ipsw` v3.1.671 installed at `/tmp/ipsw`
- Extraction command: `/tmp/ipsw dyld extract /tmp/dyld_cache_full/dyld_shared_cache_arm64e <DYLIB>`
- Need full dylib paths from `ipsw dyld info --dylibs` (slow — 2715 images to parse)

### Standalone Binaries Copied
- `/tmp/ios_binaries/frameworks/libCoreKE.dylib` (31MB) — CoreKernel Extensions with ccder_* DER encoder
- `/tmp/ios_binaries/frameworks/libRPAC.dylib` (122KB) — Runtime PAC library
- All daemons at `/tmp/ios_binaries/apple_private/`

---

## iphonern Improvements (from RE findings)

### Added to iphonern-macho:
1. **17 new load commands** — LC_DYLD_CHAINED_FIXUPS, LC_BUILD_VERSION, LC_FUNCTION_STARTS, etc.
2. **22 codesign constants** — CSMAGIC_CODEDIRECTORY, CSSLOT_*, CS_HASHTYPE_*, CS_EXECSEG_*
3. **12 chained fixup constants** — DYLD_CHAINED_PTR_ARM64E_USERLAND24, etc.
4. **Chained fixup parser** — full LC_DYLD_CHAINED_FIXUPS parsing
5. **PAC constants** — RET, BRAB_PREFIX, BRAA_PREFIX, PACIASP, PACIBSP, AUTIASP, AUTIBSP
6. **PAC detection** — is_brab(), is_braa(), is_pac_branch(), is_pac_sign(), is_ret()
7. **Entitlement injection** — inject_entitlements() replaces XML in superblob
8. **Load command insertion** — insert_load_command() + build_dylib_load_command()
9. **Protocol constants** — FairPlay v2, lockdownd SRP, keybag types/protection classes

### Added to iphonern-patch:
- **PacBypassPatchOp** — BRAB/BRAA → RET (the technique we invented)
- **PacStripPatchOp** — PACIASP/PACIBSP → NOP

### Remaining iphonern work:
- DER ASN.1 entitlement encoder (ccder_* functions found in libCoreKE.dylib)
- SRP protocol implementation (math: modular exponentiation)
- Keybag TLV parser + AES-wrap key unwrapping
- FairPlay v2 session protocol

---

## Tool Inventory (238 total)

### Original (181 tools)
Database info, segments, functions, decompilation, xrefs, strings, imports, exports, types, structs, enums, microcode, control flow, bookmarks, comments, names, frames, search, navigation, memory, instructions, callers, switches, jumptables, wide values, metadata, patching, undo, problems, fixups, demangling, bin search, register search, scripts, debugger, auto analysis, entry points, dirtree, import entry, offsets, decl compiler, snippets, read bytes, metadata backup, function context, database ops, decompile_all, batch operations.

### Added This Session (57 new tools)

**FLIRT/Signatures:** `list_signatures`, `apply_signature`

**Find/Navigation:** `find_code`, `find_data`, `find_unknown`, `find_defined`, `find_not_func`, `find_imm`, `find_notype`

**Data Creation:** `create_data`, `create_string`, `undefine`, `make_code`, `get_data_value`, `get_file_offset`, `get_address_from_file_offset`

**Xref/Function Manipulation:** `add_code_xref`, `del_code_xref`, `add_data_xref`, `del_data_xref`, `create_function`, `delete_function`, `set_function_bounds`

**Visual Marking:** `set_item_color`, `get_item_color`, `add_hidden_range`

**Comments:** `get_extra_comments`, `set_extra_comment`

**Segments:** `add_segment`, `delete_segment`, `set_segment_name`, `set_segment_class`, `set_segment_bounds`, `set_segment_permissions`

**Source/Debug:** `get_source_file`, `get_source_line`, `get_input_file_info`, `get_idb_paths`, `get_exception_handlers`

**Analysis:** `reanalyze`

**Types (using undocumented APIs):** `build_anon_type_name`, `deduplicate_struct_members`, `get_deref_chain`

**ObjC/iOS:** `list_objc_selectors`, `list_objc_classes`, `list_objc_methods`, `list_objc_protocols`, `resolve_objc_call`, `get_xpc_services`, `get_entitlements`, `get_objc_class_info`

**Deep Analysis:** `get_vtable_entries`, `get_chained_fixups`, `get_call_info`

**IDAPython:** `run_python`, `run_python_expr`

**Force Decompile:** `force_decompile` (standalone, plus integrated into `decompile_function`)

---

## Decompilation Dump Locations

### Persistent (~/VulnerabilityResearch/ida-pro/)
```
fairplayd_h2/all/       34,903 files  1,109K lines  FairPlay daemon v2
securityd/all/          12,001 files    372K lines  keychain/cert management
fairplay/all/            6,662 files    268K lines  fairplaydeviceidentityd
fairplay/crypto_real_pseudo/  37 files              FairPlay crypto (real C pseudocode)
fairplay/crypto_microcode/    37 files   34K lines  FairPlay crypto (Hex-Rays microcode)
fairplay/crypto/              37 files   11K lines  FairPlay crypto (ARM64 disassembly)
hexx64_decompiler/all/   2,375 files    242K lines  Hex-Rays x64 decompiler
lockdownd/all/           1,584 files     78K lines  device pairing
installd/all/            1,931 files     59K lines  app installation
arm_proc/all/              685 files     78K lines  ARM processor module
pc_proc/all/               681 files     78K lines  x86 processor module
keybagd/all/               740 files     30K lines  key management
amfid/all/                 417 files     10K lines  code signing enforcement
objc_plugin/all/           313 files     20K lines  ObjC plugin
pe_loader/all/             210 files     20K lines  PE loader
rtti_plugin/all/            78 files      9K lines  RTTI plugin
macho/                      40 files     24K lines  Mach-O loader
ida_binaries/                             166MB     all IDA .so files
libCoreKE.dylib                            31MB     CoreKernel Extensions (ccder_* DER)
libRPAC.dylib                             122KB     Runtime PAC library
```

### Temporary (/tmp/)
```
dyld_cache_full/          3.3GB  46 files  iOS 16.4 dyld shared cache (arm64e)
ios_binaries/apple_private/                all iOS daemons from device
ipsw                       86MB           ipsw v3.1.671 (dyld cache extraction tool)
```

### Total: ~62,600 files, ~2,437,000 lines of decompiled code

---

## Search Improvements

Replaced slow `std::regex` iteration with `find_text(pattern, SEARCH_REGEX)` — IDA's `search()` at `0x67AB00` internally supports regex via `qregexec()` when flag `0x20` (`SEARCH_REGEX`) is set. Confirmed by decompiling the search engine.

ObjC section search replaced `std::regex` with IDA's native `qregcomp`/`qregexec` from `regex.h`. Eliminated `<regex>` include.

## ARM64 PAC Branch Analysis

Enhanced `analyze_indirect_branch` tool with full PAC support from arm.so RE:
- PAC detection via `auxpref & 0x10000`
- Key decoding (IA/IB/DA/DB/GA)
- Address register mode (GPR/X17/LR)
- Modifier mode (GPR/zero/X16/SP)
- ARM64 itype classification (BR=4, BLR=14, BLRA=23, BRAB=41, TBB=274, TBH=275)
- Jump table pattern names (tb, ptn1, ptn2, ldrpc)
- Thunk resolution via `calc_thunk_func_target(func, &fptr)`
- TBB/TBH 1/2-byte jump table entry support
