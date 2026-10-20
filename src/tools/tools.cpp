#include "tools/tools.hpp"
#include <algorithm>
#include <cctype>
#include <cstdlib>

namespace ida_mcp::tools {
    namespace {
        std::string normalized_tool_profile() {
            const char *raw = std::getenv("IDA_MCP_TOOL_PROFILE");
            if (raw == nullptr || *raw == '\0')
                return "core";

            std::string value(raw);
            std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });
            return value;
        }

        bool register_advanced_tools() {
            std::string profile = normalized_tool_profile();
            return profile == "all" || profile == "full" || profile == "complete";
        }
    }

    void register_all_tools(mcp::McpServer &server) {
        // Core reverse-engineering profile: keep the surface small and useful for
        // navigation, strings, xrefs, decompilation, metadata, and Python/IDC.
        // Set IDA_MCP_TOOL_PROFILE=all before starting IDA to expose every tool.
        database::register_tools(server);
        search::register_tools(server);
        hexrays::register_tools(server);

        strings::register_tools(server);
        functions::register_tools(server);
        xrefs::register_tools(server);

        segments::register_tools(server);
        navigation::register_tools(server);
        names::register_tools(server);
        comments::register_tools(server);

        imports::register_tools(server);
        exports::register_tools(server);
        metadata::register_tools(server);

        instructions::register_tools(server);
        memory::register_tools(server);
        callers::register_tools(server);
        read_bytes::register_tools(server);
        demangling::register_tools(server);

        frames::register_tools(server);
        types::register_tools(server);
        switches::register_tools(server);

        auto_analysis::register_tools(server);
        entry_points::register_tools(server);
        exec_scripts::register_tools(server);
        function_context::register_tools(server);
        offsets::register_tools(server);
        problems::register_tools(server);
        symbols::register_tools(server);
        control_flow::register_tools(server);
        bin_search::register_tools(server);

        decompile_all::register_tools(server);
        microcode::register_tools(server);
        source_info::register_tools(server);
        objc_analysis::register_tools(server);
        objc_deep::register_tools(server);
        classes::register_tools(server);
        listing_export::register_tools(server);

        if (!register_advanced_tools())
            return;

        // Advanced, mutating, debugger, processor-specific, or niche tools.
        fixups::register_tools(server);
        debugger::register_tools(server);
        indirect_branches::register_tools(server);
        patching::register_tools(server);
        undo::register_tools(server);
        bookmarks::register_tools(server);
        reg_search::register_tools(server);
        jumptables::register_tools(server);
        decl_compiler::register_tools(server);
        snippets::register_tools(server);
        wide_values::register_tools(server);
        metadata_backup::register_tools(server);
        dirtree_tools::register_tools(server);
        import_entry::register_tools(server);
        signatures::register_tools(server);
        find_items::register_tools(server);
        data_creation::register_tools(server);
        xref_manipulation::register_tools(server);
        segment_manipulation::register_tools(server);
        xtensa_options::register_tools(server);
        cpp_class_recovery::register_tools(server);
    }
} // namespace ida_mcp::tools
