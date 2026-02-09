#pragma once

#include "common.hpp"
#include "mcp/server.hpp"
#include <memory>
#include <thread>

namespace ida_mcp::http {

class HttpServer {
public:
    HttpServer(const std::string& address, uint16_t port, mcp::McpServer& mcp_server);
    ~HttpServer();

    // Start the server (blocking)
    void run();

    // Stop the server
    void stop();

private:
    // Handle a single HTTP session
    void handle_session(tcp::socket socket) const;

    // Process HTTP request
    beast::http::response<beast::http::string_body> handle_request(
        beast::http::request<beast::http::string_body>&& request) const;

    std::string address_;
    uint16_t port_;
    mcp::McpServer& mcp_server_;
    net::io_context io_context_;
    std::unique_ptr<tcp::acceptor> acceptor_;
    bool running_;
};

} // namespace ida_mcp::http
