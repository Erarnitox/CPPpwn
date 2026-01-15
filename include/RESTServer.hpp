#pragma once

#include "HttpServer.hpp"
#include <glaze/glaze.hpp>
#include <functional>
#include <string>
#include <map>
#include <optional>

namespace cpppwn {

class RESTException;

using JsonHandler = std::function<HttpResponse(const HttpRequest&)>;
using ErrorHandler = std::function<HttpResponse(const HttpRequest&, const std::exception&)>;

//----------------------------------------
//
//----------------------------------------
struct ResourceHandlers {
  std::function<HttpResponse(const HttpRequest&)> list;
  std::function<HttpResponse(const HttpRequest&)> create;
  std::function<HttpResponse(const HttpRequest&, const std::string& id)> retrieve;
  std::function<HttpResponse(const HttpRequest&, const std::string& id)> update;
  std::function<HttpResponse(const HttpRequest&, const std::string& id)> partial_update;
  std::function<HttpResponse(const HttpRequest&, const std::string& id)> destroy;
};

//----------------------------------------
//
//----------------------------------------
class RESTServer {
public:
  explicit RESTServer(uint16_t port, const std::string& bind_addr = "0.0.0.0");

  explicit RESTServer(uint16_t port, const TlsConfig& tls_config, const std::string& bind_addr = "0.0.0.0");

  template<typename T>
  struct TypedResourceHandlers {
    std::function<std::vector<T>(const HttpRequest&)> list;
    std::function<T(const HttpRequest&, const T&)> create;
    std::function<T(const HttpRequest&, const std::string& id)> retrieve;
    std::function<T(const HttpRequest&, const std::string& id, const T&)> update;
    std::function<T(const HttpRequest&, const std::string& id, const T&)> partial_update;
    std::function<void(const HttpRequest&, const std::string& id)> destroy;
  };

  template<typename TResponse>
  void get(const std::string& path, std::function<TResponse(const HttpRequest&)> handler) {
    server_.get(path, [handler](const HttpRequest& req) {
      try {
        TResponse response = handler(req);
        std::string json = glz::write_json(response).value_or("{}");
        return HttpResponse().set_json(json);
      } catch (const std::exception& e) {
        return HttpResponse(500).set_json(R"({"error":")" + std::string(e.what()) + R"("})");
      }
    });
  }

  template<typename TRequest, typename TResponse = TRequest>
  void post(const std::string& path, std::function<TResponse(const HttpRequest&, const TRequest&)> handler) {
    server_.post(path, [handler](const HttpRequest& req) {
      try {
        TRequest request_data;
        auto error = glz::read_json(request_data, req.body);
        if(error) {
          return HttpResponse(400).set_json(R"({"error":"Invalid JSON"})");
        }

        TResponse response = handler(req, request_data);
        std::string json = glz::write_json(response).value_or("{}");
        return HttpResponse(201).set_json(json);
      } catch (const std::exception& e) {
        return HttpResponse(500).set_json(R"({"error":")" + std::string(e.what()) + R"("})");
      }
    });
  }

  template<typename TRequest, typename TResponse = TRequest>
  void put(const std::string& path, std::function<TResponse(const HttpRequest&, const TRequest&)> handler) {
    server_.put(path, [handler](const HttpRequest& req) {
      try {
        TRequest request_data;
        auto error = glz::read_json(request_data, req.body);
        if(error) {
          return HttpResponse(400).set_json(R"({"error":"Invalid JSON"})");
        }

        TResponse response = handler(req, request_data);
        std::string json = glz::write_json(response).value_or("{}");
        return HttpResponse().set_json(json);
      } catch (const std::exception& e) {
        return HttpResponse(500).set_json(R"({"error":")" + std::string(e.what()) + R"("})");
      }
    });
  }

  template<typename TRequest, typename TResponse = TRequest>
  void patch(const std::string& path, std::function<TResponse(const HttpRequest&, const TRequest&)> handler) {
    server_.patch(path, [handler](const HttpRequest& req) {
      try {
        TRequest request_data;
        auto error = glz::read_json(request_data, req.body);
        if(error) {
          return HttpResponse(400).set_json(R"({"error":"Invalid JSON"})");
        }

        TResponse response = handler(req, request_data);
        std::string json = glz::write_json(response).value_or("{}");
        return HttpResponse().set_json(json);
      } catch (const std::exception& e) {
        return HttpResponse(500).set_json(R"({"error":")" + std::string(e.what()) + R"("})");
      }
    });
  }

  template<typename TRequest, typename TResponse = TRequest>
  void del(const std::string& path, std::function<TResponse(const TRequest&)> handler) {
    server_.del(path, [handler](const TRequest& req) {
      try {
        handler(req);
        return HttpResponse(204); // No Content
      } catch (const std::exception& e) {
        return HttpResponse(500).set_json(R"({"error":")" + std::string(e.what()) + R"("})");
      }
    });
  }

  template<typename T>
  void resource(const std::string& name, struct TypedResourceHandlers<T> handlers) {
    std::string base_path = "/" + name;
    std::string id_path = base_path + "/:id";


    if(handlers.list) {
      get<std::vector<T>>(base_path, [handlers](const HttpRequest& req) {
        return handlers.list(req);
      });
    }

    // CREATE: POST /resource
    if(handlers.create) {
      post<T, T>(base_path, [handlers](const HttpRequest& req, const T& data) {
        return handlers.create(req, data);
      });
    }

    // RETRIEVE: GET /resource/:id
    if(handlers.retrieve) {
      get<T>(id_path, [handlers, name](const HttpRequest& req) {
        std::string id = extract_id_from_path(req.path, name);
        return handlers.retrieve(req, id);
      });
    }

    // UPDATE: PUT /resource/:id
    if(handlers.update) {
      put<T, T>(id_path, [handlers, name](const HttpRequest& req, const T& data) {
        std::string id = extract_id_from_path(req.path, name);
        return handlers.update(req, id, data);
      });
    }

    // PARTIAL_UPDATE: PATCH /resource/:id
    if(handlers.partial_update) {
      patch<T, T>(id_path, [handlers, name](const HttpRequest& req, const T& data) {
        std::string id = extract_id_from_path(req.path, name);
        return handlers.partial_update(req, id, data);
      });
    }

    // DESTROY: DELETE /resource/:id
    if(handlers.destroy) {
      del(id_path, [handlers, name](const HttpRequest& req) {
        std::string id = extract_id_from_path(req.path, name);
        handlers.destroy(req, id);
      });
    }
  }

  static std::string extract_id_from_path(const std::string& path, const std::string& resource);

  void get(const std::string& path, JsonHandler handler);

  void post(const std::string& path, JsonHandler handler);

  void put(const std::string& path, JsonHandler handler);

  void del(const std::string& path, JsonHandler handler);

  void patch(const std::string& path, JsonHandler handler);

  void resource(const std::string& name, const ResourceHandlers& handlers);

  void use_middleware(Middleware middleware);

  void enable_cors(const std::string& origin = "*",
    const std::string& methods = "GET, POST, PUT, DELETE, PATCH",
    const std::string& headers = "Content-Type, Authorization");

  void on_not_found(JsonHandler handler);

  void on_error(ErrorHandler handler);

  static HttpResponse json_response(int status_code, const std::map<std::string, std::string>& data = {});

  void start();

  void stop();

  [[nodiscard]] bool is_running() const noexcept;

  HttpServer& http_server();
  const HttpServer& http_server() const;

private:
  HttpResponse handle_json_request(const HttpRequest& req, JsonHandler handler);

  void setup_error_handlers();

  HttpServer server_;
  JsonHandler not_found_handler_;
  std::function<HttpResponse(const HttpRequest&, const std::exception&)> error_handler_;
};
}
