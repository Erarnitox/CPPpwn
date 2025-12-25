#pragma once

#include "Server.hpp"
#include "Remote.hpp"
#include "HttpUtils.hpp"

#include <string>
#include <map>
#include <vector>
#include <memory>
#include <atomic>

namespace cpppwn {

//----------------------------------------
//
//----------------------------------------
class HttpServer {
public:
  explicit HttpServer(uint16_t port, const std::string& bind_addr = "0.0.0.0");

  explicit HttpServer(uint16_t port, const TlsConfig& tls_config,
      const std::string& bind_addr = "0.0.0.0");

  ~HttpServer();

  void route(const std::string& method, const std::string& path, RouteHandler handler);

  void get(const std::string& path, RouteHandler handler);

  void post(const std::string& path, RouteHandler handler);

  void put(const std::string& path, RouteHandler handler);

  void del(const std::string& path, RouteHandler handler);

  void patch(const std::string& path, RouteHandler handler);

  void use_middleware(Middleware middleware);

  void serve_static(const std::string& url_prefix, const std::string& directory);

  void start();

  void stop();

  void debug_routes() const;

  [[nodiscard]] bool is_running() const noexcept;

  // Prevent copying
  HttpServer(const HttpServer&) = delete;
  HttpServer& operator=(const HttpServer&) = delete;

private:
  void handle_client(std::unique_ptr<Remote> client);
  HttpRequest parse_request(const std::string& raw_request) const;
  HttpResponse handle_static_file(const HttpRequest& request) const;

  std::unique_ptr<Server> server_;
  std::map<std::string, RouteHandler> routes_;
  std::vector<Middleware> middlewares_;
  std::map<std::string, std::string> static_routes_;
  std::atomic<bool> running_;
};

}
