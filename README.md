# IDA MCP Server

A native C++ plugin for IDA Pro that lets AI agents and LLM clients (Claude Code, Claude Desktop, Cursor, Codex, or any
[Model Context Protocol](https://modelcontextprotocol.io) client) work inside your open IDA database.

- **249 tools.** These cover disassembly, Hex-Rays decompiling, microcode, types, xrefs, control flow, Objective-C and
  C++ class recovery, patching, the debugger, and IDAPython/IDC scripting.
- **Runs inside IDA.** It is built on the IDA SDK. It has no Python bridge and needs no extra process.
- **MCP over HTTP.** Protocol versions 2024-11-05 through 2025-11-25 are supported, and the server answers on
  `http://127.0.0.1:7777/mcp`.
- **A small default tool set.** 141 tools are on by default, so the agent's context stays small. Set
  `IDA_MCP_TOOL_PROFILE=all` to turn on every tool.
- **Compatible with [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) 1.4.** `/rea/mcp` serves its read-only
  tool set (10 tools).

## Install

### Prebuilt (Linux x86-64, IDA Pro 9.5)

Download `ida_mcp_server.so` from the [latest release](https://github.com/coleleavitt/ida-mcp-server/releases/latest)
and copy it into IDA's `plugins/` folder (or `~/.idapro/plugins/`). It needs glibc 2.38 or newer, for example Ubuntu
24.04, Debian 13 or Fedora 39.

### From source

You need CMake 3.20 or newer, a C++17 compiler, Boost 1.75 or newer (headers only), nlohmann_json 3, and the IDA SDK.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
      -DIDASDK_DIR=/path/to/ida-sdk/src \
      -DIDA_INSTALL_DIR=/path/to/ida
cmake --build build -j
cp build/ida_mcp_server.so /path/to/ida/plugins/
```

To build without Hex-Rays, add `-DWITH_HEXRAYS=OFF`. The build supports Linux, macOS and Windows.

## Use

1. Open a database in IDA.
2. Start the server with **Edit → Plugins → MCP Server** or <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>M</kbd>. Run it
   again to stop it.
3. Point your MCP client at `http://127.0.0.1:7777/mcp`.

Claude Code:

```sh
claude mcp add --transport http ida http://127.0.0.1:7777/mcp
```

Clients that use an `mcpServers` JSON config:

```json
{ "mcpServers": { "ida": { "type": "http", "url": "http://127.0.0.1:7777/mcp" } } }
```

Quick check from a shell:

```sh
curl http://127.0.0.1:7777/          # status
curl http://127.0.0.1:7777/tools     # tool list with input schemas
curl -X POST http://127.0.0.1:7777/mcp -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_functions","arguments":{}}}'
```

## Tool profiles

| Profile | How to turn it on | Tools |
|---|---|---|
| `core` | default | 141: navigation, functions, strings, xrefs, decompiling, types, frames, switches, control flow, Objective-C, scripting |
| `all` | `IDA_MCP_TOOL_PROFILE=all` before starting IDA | 249: adds patching, undo, the debugger, segment and xref editing, jump tables, FLIRT signatures, fixups, bookmarks and more |

## Tools

| Area | Examples |
|---|---|
| Database | `get_database_info`, `get_binary_metadata`, `save_database`, `auto_wait`, `get_input_file_info` |
| Functions and navigation | `list_functions`, `get_function_context`, `get_func_limits`, `get_next_func`, `get_entry_points` |
| Decompiler | `decompile_function`, `batch_decompile`, `export_all_decompiled`, `get_microcode`, `force_decompile` |
| Disassembly | `decode_insn`, `print_insn`, `get_operand_info`, `export_listing`, `search_disassembly` |
| Cross-references | `get_xrefs_to`, `get_xrefs_from`, `get_callers`, `get_callees`, `find_register_access` |
| Control flow | `get_function_flowchart`, `find_block_paths`, `get_block_dominators`, `analyze_indirect_branch` |
| Types | `list_structs`, `get_struct_members`, `parse_c_declarations`, `apply_type_at_address`, `guess_function_type` |
| Strings and search | `list_strings`, `search_bytes`, `search_binary_pattern`, `find_imm`, `find_code` |
| Objective-C and C++ | `list_objc_classes`, `resolve_objc_call`, `get_entitlements`, `recover_cpp_classes`, `get_vtable_entries` |
| Editing | `set_name`, `set_cmt`, `create_function`, `create_data`, `patch_bytes`, `perform_undo` |
| Debugger | `start_debug_process`, `add_breakpoint`, `step_over`, `get_register_value`, `list_threads` |
| Scripting | `run_python`, `eval_idc`, `exec_snippet` |

To see every tool with its input schema, run `curl http://127.0.0.1:7777/tools`.

## Security

The server binds to `127.0.0.1` only and has **no authentication**. Its tools can run Python, patch bytes and start
processes under the debugger, so any local process that can reach port 7777 can do the same. Only run it on machines you
trust, and stop it when you are done.

## Notes

[RESEARCH.md](RESEARCH.md) has notes from building this plugin: SDK ABI pitfalls such as the missing `__EA64__`, and
crash fixes found by decompiling IDA's own binaries.

## License

[MIT](LICENSE). IDA Pro and the IDA SDK are products of Hex-Rays and have their own license terms.
