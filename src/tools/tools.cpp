#include "tools/tools.hpp"

namespace ida_mcp::tools {
    void register_all_tools(mcp::McpServer &server) {
        // Register all tool modules
        database::register_tools(server);
        search::register_tools(server);
        hexrays::register_tools(server);

        // Newly ported tools - batch 1
        strings::register_tools(server);
        functions::register_tools(server);
        xrefs::register_tools(server);

        // Newly ported tools - batch 2
        segments::register_tools(server);
        navigation::register_tools(server);
        names::register_tools(server);
        comments::register_tools(server);

        // Newly ported tools - batch 3 (imports/exports/metadata)
        imports::register_tools(server);
        exports::register_tools(server);
        metadata::register_tools(server);

        // Newly ported tools - batch 4 (instructions/memory/callers/demangling)
        instructions::register_tools(server);
        memory::register_tools(server);
        callers::register_tools(server);
        read_bytes::register_tools(server);
        demangling::register_tools(server);

        // Newly ported tools - batch 5 (frames/types/switches/fixups)
        frames::register_tools(server);
        types::register_tools(server);
        switches::register_tools(server);
        fixups::register_tools(server);

        // Newly ported tools - batch 6 (remaining modules)
        auto_analysis::register_tools(server);
        debugger::register_tools(server);
        entry_points::register_tools(server);
        exec_scripts::register_tools(server);
        function_context::register_tools(server);
        indirect_branches::register_tools(server);
        offsets::register_tools(server);
        problems::register_tools(server);
        symbols::register_tools(server);
        control_flow::register_tools(server);

        // New tools - batch 7 (patching/undo/bookmarks/register search/binary search)
        patching::register_tools(server);
        undo::register_tools(server);
        bookmarks::register_tools(server);
        reg_search::register_tools(server);
        bin_search::register_tools(server);

        jumptables::register_tools(server);
        decl_compiler::register_tools(server);
        snippets::register_tools(server);

        wide_values::register_tools(server);
        metadata_backup::register_tools(server);
    }
} // namespace ida_mcp::tools
