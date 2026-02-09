#include "http/server.hpp"
#include <iostream>

namespace ida_mcp::http {
    HttpServer::HttpServer(const std::string &address, uint16_t port, mcp::McpServer &mcp_server)
        : address_(address)
          , port_(port)
          , mcp_server_(mcp_server)
          , running_(false) {
    }

    HttpServer::~HttpServer() {
        stop();
    }

    void HttpServer::run() {
        try {
            auto const address = net::ip::make_address(address_);
            acceptor_ = std::make_unique<tcp::acceptor>(
                io_context_,
                tcp::endpoint{address, port_}
            );

            running_ = true;

            // Accept loop - keep accepting connections while running
            while (running_) {
                try {
                    tcp::socket socket{io_context_};

                    // Wait for connection
                    acceptor_->accept(socket);

                    // Handle in new thread
                    std::thread([this, socket = std::move(socket)]() mutable {
                        handle_session(std::move(socket));
                    }).detach();
                } catch (const boost::system::system_error &e) {
                    // Acceptor closed (stop() called)
                    if (e.code() == boost::asio::error::operation_aborted ||
                        e.code() == boost::asio::error::bad_descriptor) {
                        break;
                    }
                    throw;
                }
            }
        } catch (const std::exception &e) {
            std::cerr << "HTTP server error: " << e.what() << std::endl;
            throw;
        }
    }

    void HttpServer::stop() {
        running_ = false;
        if (acceptor_) {
            acceptor_->close();
        }
    }

    void HttpServer::handle_session(tcp::socket socket) const {
        try {
            beast::flat_buffer buffer;

            // Read HTTP request
            beast::http::request<beast::http::string_body> req;
            beast::http::read(socket, buffer, req);

            // Handle request
            auto response = handle_request(std::move(req));

            // Send response
            beast::http::write(socket, response);

            // Graceful shutdown
            socket.shutdown(tcp::socket::shutdown_send);
        } catch (const std::exception &e) {
            std::cerr << "Session error: " << e.what() << std::endl;
        }
    }

    beast::http::response<beast::http::string_body>
    HttpServer::handle_request(beast::http::request<beast::http::string_body> &&req) const {
        auto make_response = [&req](beast::http::status status, std::string body) {
            beast::http::response<beast::http::string_body> res{status, req.version()};
            res.set(beast::http::field::server, "IDA-MCP-Server/1.0");
            res.set(beast::http::field::content_type, "application/json");
            res.set(beast::http::field::access_control_allow_origin, "*");
            res.keep_alive(req.keep_alive());
            res.body() = std::move(body);
            res.prepare_payload();
            return res;
        };

        // Only accept POST requests to /mcp
        if (req.method() != beast::http::verb::post) {
            return make_response(beast::http::status::method_not_allowed,
                                 R"({"error":"Only POST requests are supported"})");
        }

        if (req.target() != "/mcp" && req.target() != "/") {
            return make_response(beast::http::status::not_found,
                                 R"({"error":"Not found"})");
        }

        // Parse JSON-RPC request
        try {
            json request_json = json::parse(req.body());
            auto mcp_request = mcp::McpRequest::from_json(request_json);

            if (!mcp_request.has_value()) {
                return make_response(beast::http::status::bad_request,
                                     R"({"error":"Invalid JSON-RPC request"})");
            }

            // Handle MCP request
            mcp::McpResponse mcp_response = mcp_server_.handle_request(mcp_request.value());

            // Return JSON-RPC response
            return make_response(beast::http::status::ok, mcp_response.to_json().dump());
        } catch (const json::parse_error &e) {
            return make_response(beast::http::status::bad_request,
                                 json{{"error", "JSON parse error"}, {"details", e.what()}}.dump());
        } catch (const std::exception &e) {
            return make_response(beast::http::status::internal_server_error,
                                 json{{"error", "Internal server error"}, {"details", e.what()}}.dump());
        }
    }
} // namespace ida_mcp::http
