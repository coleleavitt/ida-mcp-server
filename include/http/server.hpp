#pragma once

#include "common.hpp"
#include "mcp/server.hpp"
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>

namespace ida_mcp::http {

class HttpServer {
public:
    HttpServer(const std::string& address, uint16_t port, mcp::McpServer& mcp_server);
    ~HttpServer();

    // Start the server (blocking)
    void run();

    // Stop the server — waits for all in-flight sessions to finish
    void stop();

private:
    // Handle a single HTTP session
    void handle_session(tcp::socket socket);

    // Process HTTP request
    beast::http::response<beast::http::string_body> handle_request(
        beast::http::request<beast::http::string_body>&& request) const;

    // Clean up finished session threads (call while holding sessions_mutex_)
    void reap_finished_sessions();

    std::string address_;
    uint16_t port_;
    mcp::McpServer& mcp_server_;
    net::io_context io_context_;
    std::unique_ptr<tcp::acceptor> acceptor_;
    std::atomic<bool> running_{false};

    // Track in-flight session threads so we can join them on shutdown
    struct SessionEntry {
        std::thread thread;
        std::atomic<bool> finished{false};
    };
    std::mutex sessions_mutex_;
    std::vector<std::shared_ptr<SessionEntry>> sessions_;
};

} // namespace ida_mcp::http
