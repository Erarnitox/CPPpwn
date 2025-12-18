#include <HttpServer.hpp>
#include <HttpUtils.hpp>

#include <sstream>
#include <algorithm>
#include <iomanip>
#include <regex>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <ctime>

#include "Helpers.hpp"

namespace cpppwn {

//----------------------------------------
//
//----------------------------------------
HttpServer::HttpServer(uint16_t port, const std::string& bind_addr)
    : server_(std::make_unique<Server>(port, bind_addr)), running_(false) {
}

//----------------------------------------
//
//----------------------------------------
HttpServer::HttpServer(uint16_t port, const TlsConfig& tls_config,
  const std::string& bind_addr)
  : server_(std::make_unique<Server>(port, tls_config, bind_addr)), running_(false) {
}

//----------------------------------------
//
//----------------------------------------
HttpServer::~HttpServer() {
  stop();
}

//----------------------------------------
//
//----------------------------------------
void HttpServer::route(const std::string& method, const std::string& path,
  RouteHandler handler) {
    routes_[method + " " + path] = std::move(handler);
}

//----------------------------------------
//
//----------------------------------------
void HttpServer::get(const std::string& path, RouteHandler handler) {
  route("GET", path, std::move(handler));
}

//----------------------------------------
//
//----------------------------------------
void HttpServer::post(const std::string& path, RouteHandler handler) {
  route("POST", path, std::move(handler));
}

//----------------------------------------
//
//----------------------------------------
void HttpServer::put(const std::string& path, RouteHandler handler) {
  route("PUT", path, std::move(handler));
}

//----------------------------------------
//
//----------------------------------------
void HttpServer::del(const std::string& path, RouteHandler handler) {
  route("DELETE", path, std::move(handler));
}

//----------------------------------------
//
//----------------------------------------
void HttpServer::patch(const std::string& path, RouteHandler handler) {
  route("PATCH", path, std::move(handler));
}

//----------------------------------------
//
//----------------------------------------
void HttpServer::use_middleware(Middleware middleware) {
  middlewares_.push_back(std::move(middleware));
}

//----------------------------------------
//
//----------------------------------------
void HttpServer::serve_static(const std::string& url_prefix, const std::string& directory) {
  static_routes_[url_prefix] = directory;
}

//----------------------------------------
//
//----------------------------------------
HttpRequest HttpServer::parse_request(const std::string& raw_request) const {
  HttpRequest request;
  std::istringstream stream(raw_request);

  // Parse request line
  std::string request_line;
  std::getline(stream, request_line);

  std::istringstream line_stream(request_line);
  std::string full_path;
  line_stream >> request.method >> full_path >> request.http_version;

  // Parse path and query string
  size_t query_pos = full_path.find('?');
  if(query_pos != std::string::npos) {
    request.path = full_path.substr(0, query_pos);
    std::string query = full_path.substr(query_pos + 1);
    request.query_params = parse_query_string(query);
  } else {
    request.path = full_path;
  }

  // Parse headers
  std::string header_line;
  while(std::getline(stream, header_line) && header_line != "\r") {
    if(header_line.back() == '\r') header_line.pop_back();
    if(header_line.empty()) break;

    size_t colon = header_line.find(':');
    if(colon != std::string::npos) {
      std::string key = header_line.substr(0, colon);
      std::string value = header_line.substr(colon + 1);

      // Trim whitespace
      value.erase(0, value.find_first_not_of(" \t"));
      value.erase(value.find_last_not_of(" \t\r\n") + 1);

      // Convert to lowercase for case-insensitive lookup
      std::transform(key.begin(), key.end(), key.begin(), ::tolower);
      request.headers[key] = value;
    }
  }

  // Parse cookies
  if(request.has_header("cookie")) {
    request.cookies = parse_cookies(request.get_header("cookie"));
  }

  // Parse body
  std::ostringstream body_stream;
  body_stream << stream.rdbuf();
  request.body = body_stream.str();

  // Parse form data if applicable
  if(request.get_header("content-type")
      .find("application/x-www-form-urlencoded") != std::string::npos) {
        request.form_data = parse_query_string(request.body);
  }

  return request;
}

//----------------------------------------
//
//----------------------------------------
HttpResponse HttpServer::handle_static_file(const HttpRequest& request) const {
  HttpResponse response;

  // Check each static route
  for(const auto& [prefix, directory] : static_routes_) {
    if(request.path.find(prefix) == 0) {
      std::string relative_path = request.path.substr(prefix.length());

      // prevent directory traversal
      if(relative_path.find("..") != std::string::npos) {
        return response.set_status(403).set_body("Forbidden");
      }

      fs::path file_path = fs::path(directory) / relative_path;

      // If path is directory, try index.html
      if(fs::is_directory(file_path)) {
        file_path /= "index.html";
      }

      // Check if file exists
      if(not fs::exists(file_path) || not fs::is_regular_file(file_path)) {
        return response.set_status(404).set_body("Not Found");
      }

      // Read file
      std::ifstream file(file_path, std::ios::binary);
      if(not file.is_open()) {
        return response.set_status(500).set_body("Internal Server Error");
      }

      std::string content((std::istreambuf_iterator<char>(file)),
          std::istreambuf_iterator<char>());

      // Set MIME type
      std::string mime_type = get_mime_type(file_path.string());

      return response.set_status(200)
        .set_header("Content-Type", mime_type)
        .set_body(content);
    }
  }
  return response.set_status(404).set_body("Not Found");
}

//----------------------------------------
//
//----------------------------------------
void HttpServer::handle_client(std::unique_ptr<Remote> client) {
  try {
    std::string raw_request = client->recvuntil("\r\n\r\n");

    // Check if there's a body to read
    auto content_length_pos = raw_request.find("Content-Length:");
    if(content_length_pos != std::string::npos) {
      size_t start = content_length_pos + 15;
      size_t end = raw_request.find("\r\n", start);
      std::string length_str = raw_request.substr(start, end - start);

      // Trim whitespace
      length_str.erase(0, length_str.find_first_not_of(" \t"));
      length_str.erase(length_str.find_last_not_of(" \t\r\n") + 1);

      size_t content_length = std::stoull(length_str);
      if(content_length > 0) {
        std::string body = client->recv(content_length);
        raw_request += body;
      }
    }

    // Parse request
    HttpRequest request = parse_request(raw_request);
    HttpResponse response;

    // Apply middlewares
    bool should_continue = true;
    for(const auto& middleware : middlewares_) {
      should_continue = middleware(request, response);
      if(not should_continue) break;
    }

    if(should_continue) {
      // Try to find matching route
      std::string route_key = request.method + " " + request.path;
      auto route_it = routes_.find(route_key);

      if(route_it != routes_.end()) {
        response = route_it->second(request);
      } else {
        // Try static file serving
        response = handle_static_file(request);

        // If still not found, return 404
        if(response.status_code == 404 && !routes_.empty()) {
          // Check if 404 handler exists
          auto not_found = routes_.find("GET /404");
          if(not_found != routes_.end()) {
            response = not_found->second(request);
          } else {
            response.set_status(404)
                    .set_html("<html><body><h1>404 Not Found</h1></body></html>");
          }
        }
      }
    }

    // Send response
    client->send(response.to_string());
    client->close();
  } catch (const std::exception& e) {
    std::cerr << "Error handling client: " << e.what() << "\n";
  }
}

//----------------------------------------
//
//----------------------------------------
void HttpServer::start() {
  if(running_) {
    throw std::runtime_error("Server is already running");
  }
  running_ = true;
  std::cout << "Server started and listening...\n";

  while(running_) {
    try {
      auto client = server_->accept();
      std::thread(&HttpServer::handle_client, this, std::move(client)).detach();
    } catch (const std::exception& e) {
      if(running_) {
        std::cerr << "Error accepting client: " << e.what() << "\n";
      }
    }
  }
}

//----------------------------------------
//
//----------------------------------------
void HttpServer::stop() {
  if(running_) {
    running_ = false;
    server_->close();
  }
}

//----------------------------------------
//
//----------------------------------------
bool HttpServer::is_running() const noexcept {
  return running_;
}

}
