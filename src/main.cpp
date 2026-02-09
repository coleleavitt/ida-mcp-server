/*
 * IDA MCP Server Plugin
 * Exposes IDA Pro analysis via Model Context Protocol over HTTP
 */

#include "common.hpp"
#include "mcp/server.hpp"
#include "http/server.hpp"
#include "tools/tools.hpp"
#include <memory>
#include <thread>

using namespace ida_mcp;

//--------------------------------------------------------------------------
// Plugin state
//--------------------------------------------------------------------------
struct mcp_plugin_t : public plugmod_t {
    std::unique_ptr<mcp::McpServer> mcp_server;
    std::unique_ptr<ida_mcp::http::HttpServer> http_server;
    std::unique_ptr<std::thread> server_thread;
    bool server_running = false;

    virtual bool idaapi run(size_t arg) override;

    virtual ~mcp_plugin_t();
};

//--------------------------------------------------------------------------
// Initialize plugin
//--------------------------------------------------------------------------
static plugmod_t *idaapi init() {
    // Plugin can run in any processor mode
    return new mcp_plugin_t();
}

//--------------------------------------------------------------------------
// Plugin destructor - cleanup
//--------------------------------------------------------------------------
mcp_plugin_t::~mcp_plugin_t() {
    if (server_running && http_server) {
        msg("MCP Server: Stopping HTTP server...\n");
        http_server->stop();
        if (server_thread && server_thread->joinable()) {
            server_thread->join();
        }
        server_running = false;
    }
}

//--------------------------------------------------------------------------
// Run plugin
//--------------------------------------------------------------------------
bool idaapi mcp_plugin_t::run(size_t arg) {
    if (server_running) {
        // Server already running - stop it
        msg("MCP Server: Stopping...\n");
        http_server->stop();
        if (server_thread && server_thread->joinable()) {
            server_thread->join();
        }
        server_running = false;
        msg("MCP Server: Stopped\n");
        return true;
    }

    // Start server
    try {
        // Get configuration from user or use defaults
        const char *bind_addr = "127.0.0.1";
        uint16_t port = 8080;

        // Create MCP server
        mcp_server = std::make_unique<mcp::McpServer>();

        // Register all tools
        msg("MCP Server: Registering tools...\n");
        tools::register_all_tools(*mcp_server);

        auto tool_list = mcp_server->get_tools();
        msg("MCP Server: Registered %zu tools\n", tool_list.size());

        // Create HTTP server
        msg("MCP Server: Starting HTTP server on %s:%d\n", bind_addr, port);
        http_server = std::make_unique<ida_mcp::http::HttpServer>(bind_addr, port, *mcp_server);

        // Run server in background thread
        server_thread = std::make_unique<std::thread>([this]() {
            http_server->run();
        });

        server_running = true;

        msg("MCP Server: Ready! Access at http://%s:%d\n", bind_addr, port);
        msg("MCP Server: Run plugin again to stop server\n");

        return true;
    } catch (const std::exception &e) {
        warning("MCP Server error: %s", e.what());
        server_running = false;
        return false;
    }
}

//--------------------------------------------------------------------------
// Plugin metadata
//--------------------------------------------------------------------------
static const char comment[] = "Model Context Protocol server for IDA Pro";
static const char help[] =
        "IDA MCP Server Plugin\n"
        "\n"
        "This plugin exposes IDA Pro's analysis capabilities via\n"
        "the Model Context Protocol (MCP) over HTTP.\n"
        "\n"
        "Usage:\n"
        "  1. Run the plugin to start the HTTP server\n"
        "  2. Connect MCP clients to http://127.0.0.1:8080\n"
        "  3. Run the plugin again to stop the server\n"
        "\n"
        "The server provides tools for:\n"
        "  - Function analysis\n"
        "  - Cross-references\n"
        "  - String search\n"
        "  - Disassembly\n"
        "  - Hexrays decompilation (if available)\n"
        "  - And much more...\n";

static const char wanted_name[] = "MCP Server";
static const char wanted_hotkey[] = "Ctrl-Shift-M";

//--------------------------------------------------------------------------
// PLUGIN DESCRIPTION BLOCK
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_MULTI, // Plugin can work with multiple idbs in parallel
    init, // initialize
    nullptr, // terminate (can be nullptr)
    nullptr, // invoke plugin (can be nullptr, we use run() instead)
    comment, // long comment about the plugin
    help, // multiline help about the plugin
    wanted_name, // the preferred short name of the plugin
    wanted_hotkey // the preferred hotkey to run the plugin
};
