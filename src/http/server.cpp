#include "http/server.hpp"
#include <iostream>
#include <chrono>

constexpr const char* MCP_PROTOCOL_VERSION = "2025-11-25";
constexpr const char* MCP_PROTOCOL_VERSION_HEADER = "MCP-Protocol-Version";
namespace ida_mcp::http {

    HttpServer::HttpServer(const std::string &address, uint16_t port, mcp::McpServer &mcp_server,
                           mcp::McpServer *rea_server)
        : address_(address)
          , port_(port)
          , mcp_server_(mcp_server)
          , rea_server_(rea_server) {
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

    void HttpServer::bind() {
        auto const address = net::ip::make_address(address_);

        acceptor_ = std::make_unique<tcp::acceptor>(io_context_);
        acceptor_->open(tcp::v4());
        acceptor_->set_option(net::socket_base::reuse_address(true));
        acceptor_->bind(tcp::endpoint{address, port_});
        acceptor_->listen(net::socket_base::max_listen_connections);
    }

    void HttpServer::run() {
        running_.store(true);

        while (running_.load()) {
            try {
                tcp::socket socket{io_context_};
                acceptor_->accept(socket);

                if (!running_.load())
                    break;

                auto entry = std::make_shared<SessionEntry>();
                {
                    std::lock_guard<std::mutex> lock(sessions_mutex_);
                    reap_finished_sessions();
                    sessions_.push_back(entry);
                }

                entry->thread = std::thread([this, s = std::move(socket), entry]() mutable {
                    handle_session(std::move(s));
                    entry->finished.store(true);
                });
            } catch (const boost::system::system_error &e) {
                if (e.code() == boost::asio::error::operation_aborted ||
                    e.code() == boost::asio::error::bad_descriptor) {
                    break;
                }
                if (!running_.load())
                    break;
                std::cerr << "HTTP server accept error: " << e.what() << std::endl;
            }
        }
    }

    void HttpServer::stop() {
        bool expected = true;
        if (!running_.compare_exchange_strong(expected, false))
            return;

        // Close acceptor first
        boost::system::error_code ec;
        if (acceptor_ && acceptor_->is_open()) {
            acceptor_->close(ec);
        }

        // Make a self-connection to wake up the blocking accept() call
        // This is necessary because acceptor_->close() doesn't reliably
        // interrupt a blocking accept() on all systems (especially Linux)
        try {
            tcp::socket wake_socket(io_context_);
            wake_socket.connect(tcp::endpoint(
                net::ip::make_address(address_), port_), ec);
            // Connection will fail since acceptor is closed, but that's fine -
            // the point is to unblock accept()
        } catch (...) {
            // Ignore errors - we just want to wake up the accept thread
        }

        // Join all session threads
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
            res.set(MCP_PROTOCOL_VERSION_HEADER, MCP_PROTOCOL_VERSION);
            res.keep_alive(false);
            res.body() = std::move(body);
            res.prepare_payload();
            return res;
        };

        auto make_empty_response = [&req](beast::http::status status,
                                          const char *allow = nullptr) {
            beast::http::response<beast::http::string_body> res{status, req.version()};
            res.set(beast::http::field::server, "IDA-MCP-Server/1.0");
            res.set(MCP_PROTOCOL_VERSION_HEADER, MCP_PROTOCOL_VERSION);
            if (allow != nullptr)
                res.set(beast::http::field::allow, allow);
            res.keep_alive(false);
            res.prepare_payload();
            return res;
        };

        // Build a spec-compliant JSON-RPC 2.0 error envelope response.
        auto make_jsonrpc_error = [&make_response](beast::http::status status,
                                                   const json &id, int code,
                                                   const std::string &message) {
            json body = {
                {"jsonrpc", "2.0"},
                {"id", id},
                {"error", {{"code", code}, {"message", message}}}
            };
            return make_response(status, body.dump());
        };

        // Only known MCP protocol versions are accepted in the request header.
        auto is_known_protocol_version = [](const std::string &v) {
            return v == "2024-11-05" || v == "2025-03-26" ||
                   v == "2025-06-18" || v == "2025-11-25";
        };

        std::string target(req.target());
        std::string target_path = target.substr(0, target.find('?'));

        // Browser/curl-friendly discovery endpoints. Tool execution remains POST-only
        // because many tools can mutate the IDB or debugger state.
        if (req.method() == beast::http::verb::get) {
            // MCP clients open an SSE stream with GET; this stateless server has none.
            auto accept = req.find(beast::http::field::accept);
            if (accept != req.end() &&
                std::string_view(accept->value()).find("text/event-stream") != std::string_view::npos) {
                return make_empty_response(beast::http::status::method_not_allowed, "POST");
            }

            if (target_path == "/" || target_path == "/mcp" || target_path == "/health") {
                json body = {
                    {"server", "ida-mcp-server"},
                    {"status", "ready"},
                    {"protocolVersion", MCP_PROTOCOL_VERSION},
                    {"mcpEndpoint", "/mcp"},
                    {"toolsEndpoint", "/tools"},
                    {"usage", {
                        {"initialize", "POST /mcp with a JSON-RPC initialize request"},
                        {"listTools", "GET /tools or POST /mcp tools/list"},
                        {"callTools", "POST /mcp tools/call"}
                    }}
                };
                return make_response(beast::http::status::ok, body.dump());
            }

            if (target_path == "/tools" || target_path == "/tools/list") {
                json tools = json::array();
                for (const auto &tool: mcp_server_.get_tools()) {
                    tools.push_back(tool.to_json());
                }

                json body = {
                    {"tools", tools},
                    {"count", tools.size()}
                };
                return make_response(beast::http::status::ok, body.dump());
            }

            return make_jsonrpc_error(beast::http::status::not_found, nullptr,
                                      mcp::error_codes::INVALID_REQUEST, "Not found");
        }

        // StreamableHTTP: DELETE (session termination) is not offered by this
        // stateless server. Advertise the supported methods on 405.
        if (req.method() == beast::http::verb::delete_) {
            return make_empty_response(beast::http::status::method_not_allowed, "GET, POST");
        }

        if (req.method() != beast::http::verb::post) {
            return make_jsonrpc_error(beast::http::status::method_not_allowed, nullptr,
                                      mcp::error_codes::INVALID_REQUEST,
                                      "Only GET and POST requests are supported");
        }

        mcp::McpServer *server = nullptr;
        if (target_path == "/mcp" || target_path == "/")
            server = &mcp_server_;
        else if (target_path == "/rea/mcp")
            server = rea_server_;
        if (server == nullptr) {
            return make_jsonrpc_error(beast::http::status::not_found, nullptr,
                                      mcp::error_codes::INVALID_REQUEST, "Not found");
        }

        // Validate the MCP-Protocol-Version request header when present (per 2025-06-18
        // spec). An absent header is allowed for backwards compatibility.
        {
            auto it = req.find(MCP_PROTOCOL_VERSION_HEADER);
            if (it != req.end()) {
                std::string ver{it->value()};
                if (!is_known_protocol_version(ver)) {
                    return make_jsonrpc_error(beast::http::status::bad_request, nullptr,
                                              mcp::error_codes::INVALID_REQUEST,
                                              "Unsupported MCP-Protocol-Version: " + ver);
                }
            }
        }

        try {
            json request_json = json::parse(req.body());

            // Best-effort id extraction so error responses can be correlated.
            json err_id = nullptr;
            if (request_json.is_object()) {
                auto id_it = request_json.find("id");
                if (id_it != request_json.end() &&
                    (id_it->is_number() || id_it->is_string()))
                    err_id = *id_it;
            }

            auto mcp_request = mcp::McpRequest::from_json(request_json);

            if (!mcp_request.has_value()) {
                return make_jsonrpc_error(beast::http::status::bad_request, err_id,
                                          mcp::error_codes::INVALID_REQUEST,
                                          "Invalid JSON-RPC request");
            }

            mcp::McpResponse mcp_response = server->handle_request(mcp_request.value());

            // MCP notifications (no id) get 202 Accepted with no body per StreamableHTTP spec
            if (mcp_response.is_notification) {
                return make_empty_response(beast::http::status::accepted);
            }

            return make_response(beast::http::status::ok, mcp_response.to_json().dump());
        } catch (const json::parse_error &e) {
            return make_jsonrpc_error(beast::http::status::bad_request, nullptr,
                                      mcp::error_codes::PARSE_ERROR,
                                      std::string("JSON parse error: ") + e.what());
        } catch (const std::exception &e) {
            return make_jsonrpc_error(beast::http::status::internal_server_error, nullptr,
                                      mcp::error_codes::INTERNAL_ERROR,
                                      std::string("Internal server error: ") + e.what());
        }
    }
} // namespace ida_mcp::http
