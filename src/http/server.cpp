#include "http/server.hpp"
#include <iostream>
#include <chrono>

namespace ida_mcp::http {
    HttpServer::HttpServer(const std::string &address, uint16_t port, mcp::McpServer &mcp_server)
        : address_(address)
          , port_(port)
          , mcp_server_(mcp_server) {
    }

    HttpServer::~HttpServer() {
        stop();
    }

    void HttpServer::reap_finished_sessions() {
        sessions_.erase(
            std::remove_if(sessions_.begin(), sessions_.end(),
                           [](const std::shared_ptr<SessionEntry> &entry) {
                               if (entry->finished.load()) {
                                   if (entry->thread.joinable())
                                       entry->thread.join();
                                   return true;
                               }
                               return false;
                           }),
            sessions_.end());
    }

    void HttpServer::run() {
        try {
            auto const address = net::ip::make_address(address_);
            acceptor_ = std::make_unique<tcp::acceptor>(
                io_context_,
                tcp::endpoint{address, port_}
            );

            running_.store(true);

            while (running_.load()) {
                try {
                    tcp::socket socket{io_context_};
                    acceptor_->accept(socket);

                    if (!running_.load())
                        break;

                    auto entry = std::make_shared<SessionEntry>();

                    entry->thread = std::thread([this, s = std::move(socket), entry]() mutable {
                        handle_session(std::move(s));
                        entry->finished.store(true);
                    }); {
                        std::lock_guard<std::mutex> lock(sessions_mutex_);
                        reap_finished_sessions();
                        sessions_.push_back(std::move(entry));
                    }
                } catch (const boost::system::system_error &e) {
                    if (e.code() == boost::asio::error::operation_aborted ||
                        e.code() == boost::asio::error::bad_descriptor) {
                        break;
                    }
                    if (!running_.load())
                        break;
                    throw;
                }
            }
        } catch (const std::exception &e) {
            std::cerr << "HTTP server error: " << e.what() << std::endl;
            throw;
        }
    }

    void HttpServer::stop() {
        bool expected = true;
        if (!running_.compare_exchange_strong(expected, false))
            return;

        if (acceptor_) {
            boost::system::error_code ec;
            acceptor_->close(ec);
        }

        std::lock_guard<std::mutex> lock(sessions_mutex_);
        for (auto &entry: sessions_) {
            if (entry->thread.joinable())
                entry->thread.join();
        }
        sessions_.clear();
    }

    void HttpServer::handle_session(tcp::socket socket) {
        try {
            beast::flat_buffer buffer;
            beast::http::request<beast::http::string_body> req;
            beast::http::read(socket, buffer, req);

            auto response = handle_request(std::move(req));
            beast::http::write(socket, response);

            boost::system::error_code ec;
            socket.shutdown(tcp::socket::shutdown_send, ec);
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

        auto make_empty_response = [&req](beast::http::status status) {
            beast::http::response<beast::http::string_body> res{status, req.version()};
            res.set(beast::http::field::server, "IDA-MCP-Server/1.0");
            res.set(beast::http::field::access_control_allow_origin, "*");
            res.keep_alive(req.keep_alive());
            res.prepare_payload();
            return res;
        };

        // StreamableHTTP: GET requests are used for SSE streams — return 405 to signal
        // that this server does not offer a standalone SSE stream (clients handle this gracefully)
        if (req.method() == beast::http::verb::get) {
            return make_empty_response(beast::http::status::method_not_allowed);
        }

        // StreamableHTTP: DELETE requests are used for session termination
        if (req.method() == beast::http::verb::delete_) {
            return make_empty_response(beast::http::status::method_not_allowed);
        }

        if (req.method() != beast::http::verb::post) {
            return make_response(beast::http::status::method_not_allowed,
                                 R"({"error":"Only POST requests are supported"})");
        }

        if (req.target() != "/mcp" && req.target() != "/") {
            return make_response(beast::http::status::not_found,
                                 R"({"error":"Not found"})");
        }

        try {
            json request_json = json::parse(req.body());
            auto mcp_request = mcp::McpRequest::from_json(request_json);

            if (!mcp_request.has_value()) {
                return make_response(beast::http::status::bad_request,
                                     R"({"error":"Invalid JSON-RPC request"})");
            }

            mcp::McpResponse mcp_response = mcp_server_.handle_request(mcp_request.value());

            // MCP notifications (no id) get 202 Accepted with no body per StreamableHTTP spec
            if (mcp_response.is_notification) {
                return make_empty_response(beast::http::status::accepted);
            }

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
