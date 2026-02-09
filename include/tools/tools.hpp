#pragma once

#include "common.hpp"
#include "mcp/server.hpp"

namespace ida_mcp::tools {

// Register all tools with the MCP server
void register_all_tools(mcp::McpServer& server);

// Individual tool registration functions
namespace database {
    void register_tools(mcp::McpServer& server);
}

namespace segments {
    void register_tools(mcp::McpServer& server);
}

namespace functions {
    void register_tools(mcp::McpServer& server);
}

namespace xrefs {
    void register_tools(mcp::McpServer& server);
}

namespace hexrays {
    void register_tools(mcp::McpServer& server);
}

namespace strings {
    void register_tools(mcp::McpServer& server);
}

namespace search {
    void register_tools(mcp::McpServer& server);
}

namespace instructions {
    void register_tools(mcp::McpServer& server);
}

namespace navigation {
    void register_tools(mcp::McpServer& server);
}

namespace comments {
    void register_tools(mcp::McpServer& server);
}

namespace names {
    void register_tools(mcp::McpServer& server);
}

namespace frames {
    void register_tools(mcp::McpServer& server);
}

namespace types {
    void register_tools(mcp::McpServer& server);
}

namespace imports {
    void register_tools(mcp::McpServer& server);
}

namespace exports {
    void register_tools(mcp::McpServer& server);
}

namespace metadata {
    void register_tools(mcp::McpServer& server);
}

namespace memory {
    void register_tools(mcp::McpServer& server);
}

namespace callers {
    void register_tools(mcp::McpServer& server);
}

namespace read_bytes {
    void register_tools(mcp::McpServer& server);
}

namespace demangling {
    void register_tools(mcp::McpServer& server);
}

namespace switches {
    void register_tools(mcp::McpServer& server);
}

namespace fixups {
    void register_tools(mcp::McpServer& server);
}

namespace auto_analysis {
    void register_tools(mcp::McpServer& server);
}

namespace debugger {
    void register_tools(mcp::McpServer& server);
}

namespace entry_points {
    void register_tools(mcp::McpServer& server);
}

namespace exec_scripts {
    void register_tools(mcp::McpServer& server);
}

namespace function_context {
    void register_tools(mcp::McpServer& server);
}

namespace indirect_branches {
    void register_tools(mcp::McpServer& server);
}

namespace offsets {
    void register_tools(mcp::McpServer& server);
}


namespace problems {
    void register_tools(mcp::McpServer& server);
}

namespace symbols {
    void register_tools(mcp::McpServer& server);
}

namespace control_flow {
    void register_tools(mcp::McpServer& server);
}

namespace patching {
    void register_tools(mcp::McpServer& server);
}

namespace undo {
    void register_tools(mcp::McpServer& server);
}

namespace bookmarks {
    void register_tools(mcp::McpServer& server);
}

namespace reg_search {
    void register_tools(mcp::McpServer& server);
}

namespace bin_search {
    void register_tools(mcp::McpServer& server);
}

namespace jumptables {
    void register_tools(mcp::McpServer& server);
}

namespace decl_compiler {
    void register_tools(mcp::McpServer& server);
}

namespace snippets {
    void register_tools(mcp::McpServer& server);
}

namespace wide_values {
    void register_tools(mcp::McpServer& server);
}

namespace metadata_backup {
    void register_tools(mcp::McpServer& server);
}

} // namespace ida_mcp::tools
