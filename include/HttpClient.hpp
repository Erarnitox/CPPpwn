#pragma once

#include "HttpUtils.hpp"
#include <memory>
#include <string>
#include <map>
#include <curl/curl.h>

namespace cpppwn {

class CurlHandle;

//----------------------------------------
// RAII wrapper for CURL handle
//----------------------------------------
class CurlHandle {
public:
  CurlHandle() : handle_(curl_easy_init()) {
    if(not handle_) {
      throw std::runtime_error("Failed to initialize CURL");
    }
  }
  
  ~CurlHandle() {
    if(handle_) {
      curl_easy_cleanup(handle_);
    }
  }
  
  // Non-copyable
  CurlHandle(const CurlHandle&) = delete;
  CurlHandle& operator=(const CurlHandle&) = delete;
  
  // Movable
  CurlHandle(CurlHandle&& other) noexcept : handle_(other.handle_) {
    other.handle_ = nullptr;
  }
  
  CurlHandle& operator=(CurlHandle&& other) noexcept {
    if(this != &other) {
      if(handle_) curl_easy_cleanup(handle_);
      handle_ = other.handle_;
      other.handle_ = nullptr;
    }
    return *this;
  }
  
  CURL* get() { return handle_; }
  
private:
  CURL* handle_;
};

//----------------------------------------
// RAII wrapper for curl_slist
//----------------------------------------
class CurlHeaders {
public:
  CurlHeaders() : list_(nullptr) {}
  
  ~CurlHeaders() {
    if (list_) {
      curl_slist_free_all(list_);
    }
  }
  
  CurlHeaders(const CurlHeaders&) = delete;
  CurlHeaders& operator=(const CurlHeaders&) = delete;
  
  void append(const std::string& header) {
    list_ = curl_slist_append(list_, header.c_str());
  }
  
  curl_slist* get() { return list_; }
  
private:
  curl_slist* list_;
};

//----------------------------------------
// HttpClient - Modern C++ wrapper around libcurl
//----------------------------------------
class HttpClient {
public:
  HttpClient() : HttpClient(HttpConfig{}) {}
  
  explicit HttpClient(const HttpConfig& config);
  
  
  // Core request method
  [[nodiscard]] HttpResponse request(
    const std::string& method,
    const std::string& url,
    const HttpHeaders& headers = {},
    const std::string& body = ""
  );
  
  // Convenience methods
  [[nodiscard]] HttpResponse get(
    const std::string& url,
    const HttpHeaders& headers = {}
  );
  
  [[nodiscard]] HttpResponse post(
    const std::string& url,
    const std::string& body,
    const HttpHeaders& headers = {}
  );
  
  [[nodiscard]] HttpResponse post_form(
    const std::string& url,
    const std::map<std::string, std::string>& form_data,
    const HttpHeaders& headers = {}
  );
  
  [[nodiscard]] HttpResponse post_json(
    const std::string& url,
    const std::string& json,
    const HttpHeaders& headers = {}
  );
  
  [[nodiscard]] HttpResponse put(
    const std::string& url,
    const std::string& body,
    const HttpHeaders& headers = {}
  );
  
  [[nodiscard]] HttpResponse del(
    const std::string& url,
    const HttpHeaders& headers = {}
  );
  
  [[nodiscard]] HttpResponse head(
    const std::string& url,
    const HttpHeaders& headers = {}
  );
  
  [[nodiscard]] HttpResponse patch(
    const std::string& url,
    const std::string& body,
    const HttpHeaders& headers = {}
  );
  
  [[nodiscard]] HttpResponse options(
    const std::string& url,
    const HttpHeaders& headers = {}
  );
  
  // File download
  bool download(const std::string& url, const std::string& output_path);
  
  // Cookie utilities
  static std::map<std::string, std::string> get_cookies(const HttpResponse& response);
  
  static HttpHeaders with_cookies(
    const HttpHeaders& headers,
    const std::map<std::string, std::string>& cookies
  );
  
  // Configuration access
  [[nodiscard]] const HttpConfig& config() const noexcept { 
    return config_; 
  }
  
  void set_config(const HttpConfig& config) { 
    config_ = config; 
  }
  
  // Cookie management
  [[nodiscard]] const std::map<std::string, std::string>& cookies() const noexcept { 
    return config_.cookies;
  }
  
  void set_cookie(const std::string& key, const std::string& value);
  
  void set_cookies(const std::map<std::string, std::string>& cookies) {
    config_.cookies = cookies;
  }
  
  void clear_cookies();
  
  // Header management
  void set_header(const std::string& key, const std::string& value);

private:
  HttpConfig config_;
  std::unique_ptr<CurlHandle> curl_handle_;
  HttpHeaders default_headers_;
};

} // namespace cpppwn