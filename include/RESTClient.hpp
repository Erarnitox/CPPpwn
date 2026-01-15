#pragma once

#include "HttpClient.hpp"
#include <glaze/glaze.hpp>
#include <string>
#include <map>
#include <optional>
#include <stdexcept>

namespace cpppwn {

//----------------------------------------
//
//----------------------------------------
class RESTException : public std::runtime_error {
  public:
    int status_code;
    std::string status_message;
    std::string response_body;

    RESTException(int code, const std::string& message, const std::string& body)
        : std::runtime_error("REST API Error " + std::to_string(code) + ": " + message),
          status_code(code), status_message(message), response_body(body) {
    }
};

//----------------------------------------
//
//----------------------------------------
struct PaginatedResponse {
    std::string data;  // JSON data
    int page = 1;      // Current page
    int per_page = 20; // Items per page
    int total = 0;     // Total items
};

//----------------------------------------
//
//----------------------------------------
class RESTClient {
public:
  explicit RESTClient(const std::string& base_url, const HttpConfig& config = HttpConfig());

  void set_auth_bearer(const std::string& token);

  void set_auth_basic(const std::string& username, const std::string& password);

  void set_auth_api_key(const std::string& key, const std::string& header_name = "X-API-Key");

  void set_header(const std::string& name, const std::string& value);

  template<typename T>
  T get(const std::string& endpoint, const HttpHeaders& headers = {}) {
    std::string json = get(endpoint, headers);

    T result;
    auto error = glz::read_json(result, json);

    if(error) {
      throw std::runtime_error("JSON deserialization failed: " + glz::format_error(error, json));
    }

    return result;
  }

  template<typename TRequest, typename TResponse = TRequest>
  TResponse post(const std::string& endpoint, const TRequest& data, const HttpHeaders& headers = {}) {
    std::string json = glz::write_json(data).value_or("{}");
    std::string response_json = post(endpoint, json, headers);

    TResponse result;
    auto error = glz::read_json(result, response_json);

    if(error) {
      throw std::runtime_error("JSON deserialization failed: " + glz::format_error(error, response_json));
    }

    return result;
  }

  template<typename TRequest, typename TResponse = TRequest>
  TResponse put(const std::string& endpoint, const TRequest& data, const HttpHeaders& headers = {}) {
    std::string json = glz::write_json(data);
    std::string response_json = put(endpoint, json, headers);

    TResponse result;
    auto error = glz::read_json(result, response_json);

    if(error) {
      throw std::runtime_error("JSON deserialization failed: " + glz::format_error(error, response_json));
    }

    return result;
  }

  template<typename TRequest, typename TResponse = TRequest>
  TResponse patch(const std::string& endpoint, const TRequest& data, const HttpHeaders& headers = {}) {
    std::string json = glz::write_json(data);
    std::string response_json = patch(endpoint, json, headers);

    TResponse result;
    auto error = glz::read_json(result, response_json);
    if(error) {
      throw std::runtime_error("JSON deserialization failed: " + glz::format_error(error, response_json));
    }

    return result;
  }

  template<typename T>
  std::vector<T> list(const std::string& resource,
    const std::map<std::string, std::string>& query_params = {}, const HttpHeaders& headers = {}) {
        std::string json = list(resource, query_params, headers);

        std::vector<T> result;
        auto error = glz::read_json(result, json);

        if(error) {
          throw std::runtime_error("JSON deserialization failed: " + glz::format_error(error, json));
        }

        return result;
  }

  template<typename T>
  T retrieve(const std::string& resource, const std::string& id, const HttpHeaders& headers = {}) {
    std::string json = retrieve(resource, id, headers);

    T result;
    auto error = glz::read_json(result, json);

    if(error) {
      throw std::runtime_error("JSON deserialization failed: " + glz::format_error(error, json));
    }

    return result;
  }

  template<typename T>
  T create(const std::string& resource, const T& data, const HttpHeaders& headers = {}) {
    std::string json = glz::write_json(data);
    std::string response_json = create(resource, json, headers);

    T result;
    auto error = glz::read_json(result, response_json);

    if(error) {
      throw std::runtime_error("JSON deserialization failed: " + glz::format_error(error, response_json));
    }

    return result;
  }

  template<typename T>
  T update(const std::string& resource, const std::string& id, const T& data, const HttpHeaders& headers = {}) {
    std::string json = glz::write_json(data);
    std::string response_json = update(resource, id, json, headers);

    T result;
    auto error = glz::read_json(result, response_json);

    if(error) {
      throw std::runtime_error("JSON deserialization failed: " + glz::format_error(error, response_json));
    }

    return result;
  }

  template<typename T>
  T partial_update(const std::string& resource, const std::string& id, const T& data, const HttpHeaders& headers = {}) {
    std::string json = glz::write_json(data);
    std::string response_json = partial_update(resource, id, json, headers);

    T result;
    auto error = glz::read_json(result, response_json);

    if(error) {
      throw std::runtime_error("JSON deserialization failed: " + glz::format_error(error, response_json));
    }

    return result;
  }

  void destroy(const std::string& resource, const std::string& id, const HttpHeaders& headers = {});

  template<typename T>
  std::pair<std::vector<T>, PaginatedResponse> get_paginated(
    const std::string& endpoint, int page = 1, int per_page = 20, const HttpHeaders& headers = {}) {
      auto response = get_paginated(endpoint, page, per_page, headers);

      std::vector<T> items;
      auto error = glz::read_json(items, response.data);

      if(error) {
        throw std::runtime_error("JSON deserialization failed: " + glz::format_error(error, response.data));
      }

      return {items, response};
  }

  HttpClient& http_client();
  const HttpClient& http_client() const;

private:
  std::string get(const std::string& endpoint, const HttpHeaders& headers);

  std::string post(const std::string& endpoint, const std::string& json_body, const HttpHeaders& headers);

  std::string put(const std::string& endpoint, const std::string& json_body, const HttpHeaders& headers);

  std::string patch(const std::string& endpoint, const std::string& json_body, const HttpHeaders& headers);

  std::string del(const std::string& endpoint, const HttpHeaders& headers);

  std::string list(const std::string& resource, const std::map<std::string, std::string>& query_params, const HttpHeaders& headers);

  std::string retrieve(const std::string& resource, const std::string& id, const HttpHeaders& headers);

  std::string create(const std::string& resource, const std::string& json_body, const HttpHeaders& headers);

  std::string update(const std::string& resource, const std::string& id, const std::string& json_body, const HttpHeaders& headers);

  std::string partial_update(const std::string& resource, const std::string& id, const std::string& json_body, const HttpHeaders& headers);

  PaginatedResponse get_paginated(const std::string& endpoint, int page, int per_page, const HttpHeaders& headers);

  HttpHeaders build_headers(const HttpHeaders& additional) const;

  std::string build_url(const std::string& endpoint) const;

  std::string request_json(const std::string& method, const std::string& endpoint, const std::string& json_body, const HttpHeaders& headers);

  enum class AuthType { None, Bearer, Basic, ApiKey };

  std::string base_url_;
  HttpClient client_;
  HttpHeaders default_headers_;

  AuthType auth_type_ = AuthType::None;
  std::string auth_token_;
  std::string auth_username_;
  std::string auth_password_;
  std::string api_key_;
  std::string api_key_header_ = "X-API-Key";
};

}
