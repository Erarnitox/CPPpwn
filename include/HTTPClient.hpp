#pragma once

#include "Remote.hpp"
#include <string>
#include <map>
#include <memory>
#include <optional>
#include <cstdint>
#include <fstream>
#include <iostream>

namespace cpppwn {

using HttpHeaders = std::map<std::string, std::string>;

//----------------------------------------
//
//----------------------------------------
enum class BrowserType {
  Chrome,
  Firefox,
  Safari,
  Edge
};

//----------------------------------------
//
//----------------------------------------
struct HttpResponse {
  int status_code = 0;
  std::string status_message;
  HttpHeaders headers;
  std::string body;
    
  //----------------------------------------
  //
  //----------------------------------------
  [[nodiscard]] bool ok() const noexcept {
    return status_code >= 200 && status_code < 300;
  }
    
  //----------------------------------------
  //
  //----------------------------------------
  [[nodiscard]] std::string get_header(const std::string& key) const {
    std::string lower_key = key;
    std::transform(lower_key.begin(), lower_key.end(), lower_key.begin(), ::tolower);
        
    auto it = headers.find(lower_key);
    return (it != headers.end()) ? it->second : "";
  }
    
  //----------------------------------------
  //
  //----------------------------------------
  [[nodiscard]] bool has_header(const std::string& key) const {
    std::string lower_key = key;
    std::transform(lower_key.begin(), lower_key.end(), lower_key.begin(), ::tolower);
    return headers.find(lower_key) != headers.end();
  }
};

//----------------------------------------
//
//----------------------------------------
struct HttpConfig {
  std::string user_agent = "cpppwn-http/1.0";   // User-Agent header (if not emulating browser)
  bool follow_redirects = true;                 // Follow HTTP redirects
  size_t max_redirects = 10;                    // Maximum number of redirects
  bool verify_ssl = true;                       // Verify SSL certificates
  bool verbose = false;                         // Print request/response for debugging
  std::string proxy_url;                        // Proxy URL (empty for no proxy)
  size_t redirect_count = 0;                    // Internal redirect counter
    
  BrowserType browser_type = BrowserType::Chrome;  // Browser to emulate
  bool send_browser_headers = true;                // Send realistic browser headers
  bool human_like_timing = false;                  // Add random delays to mimic humans
  bool send_dnt = false;                           // Send Do-Not-Track header
  std::string referer;                             // Referer header for navigation
  bool auto_store_cookies = true;                  // Automatically store cookies
    
  //----------------------------------------
  //
  //----------------------------------------
  HttpConfig() = default;
    
  //----------------------------------------
  //
  //----------------------------------------
  explicit HttpConfig(std::string ua) : user_agent(std::move(ua)), send_browser_headers(false) {
  }
    
  //----------------------------------------
  //
  //----------------------------------------
  explicit HttpConfig(BrowserType browser) : browser_type(browser), send_browser_headers(true) {
  }
};

//----------------------------------------
//
//----------------------------------------
class ParsedUrl {
  public:
    std::string scheme;
    std::string host;
    uint16_t port = 0;
    std::string path;
    std::string query;
    std::string fragment;
    
    bool is_https() const { 
      return scheme == "https"; 
    }
    
    uint16_t get_port() const {
      if(port != 0) return port;
      return is_https() ? 443 : 80;
    }
    
    std::string get_path_with_query() const {
      std::string result = path.empty() ? "/" : path;
      if(not query.empty()) {
        result += "?" + query;
      }
      return result;
    }
};

//----------------------------------------
//
//----------------------------------------
class HttpClient {
public:
    //----------------------------------------
    //
    //----------------------------------------
    HttpClient() : HttpClient(HttpConfig{}) {
    }
    
    //----------------------------------------
    //
    //----------------------------------------
    explicit HttpClient(const HttpConfig& config);
    
    //----------------------------------------
    //
    //----------------------------------------
    [[nodiscard]] HttpResponse request(
      const std::string& method,
      const std::string& url,
      const HttpHeaders& headers = {},
      const std::string& body = ""
    );
    
    //----------------------------------------
    //
    //----------------------------------------
    [[nodiscard]] HttpResponse get(
      const std::string& url,
      const HttpHeaders& headers = {}
    );
    
    //----------------------------------------
    //
    //----------------------------------------
    [[nodiscard]] HttpResponse post(
      const std::string& url,
      const std::string& body,
      const HttpHeaders& headers = {}
    );
    
    //----------------------------------------
    //
    //----------------------------------------
    [[nodiscard]] HttpResponse post_form(
      const std::string& url,
      const std::map<std::string, std::string>& form_data,
      const HttpHeaders& headers = {}
    );
    
    //----------------------------------------
    //
    //----------------------------------------
    [[nodiscard]] HttpResponse post_json(
      const std::string& url,
      const std::string& json,
      const HttpHeaders& headers = {}
    );
    
    //----------------------------------------
    //
    //----------------------------------------
    [[nodiscard]] HttpResponse put(
      const std::string& url,
      const std::string& body,
      const HttpHeaders& headers = {}
    );
    
    //----------------------------------------
    //
    //----------------------------------------
    [[nodiscard]] HttpResponse del(
      const std::string& url,
      const HttpHeaders& headers = {}
    );
    
    //----------------------------------------
    //
    //----------------------------------------
    [[nodiscard]] HttpResponse head(
      const std::string& url,
      const HttpHeaders& headers = {}
    );
    
    //----------------------------------------
    //
    //----------------------------------------
    [[nodiscard]] HttpResponse patch(
      const std::string& url,
      const std::string& body,
      const HttpHeaders& headers = {}
    );
    
    //----------------------------------------
    //
    //----------------------------------------
    [[nodiscard]] HttpResponse options(
      const std::string& url,
      const HttpHeaders& headers = {}
    );
    
    //----------------------------------------
    //
    //----------------------------------------
    bool download(const std::string& url, const std::string& output_path);
    
    //----------------------------------------
    //
    //----------------------------------------
    static std::map<std::string, std::string> get_cookies(const HttpResponse& response);
    
    //----------------------------------------
    //
    //----------------------------------------
    static HttpHeaders with_cookies(
      const HttpHeaders& headers,
      const std::map<std::string, std::string>& cookies
    );
    
    //----------------------------------------
    //
    //----------------------------------------
    [[nodiscard]] const HttpConfig& config() const noexcept { return config_; }
    
    //----------------------------------------
    //
    //----------------------------------------
    void set_config(const HttpConfig& config) { config_ = config; }
    
    //----------------------------------------
    //
    //----------------------------------------
    [[nodiscard]] const std::map<std::string, std::string>& cookies() const noexcept { 
      return cookie_jar_; 
    }
    
    //----------------------------------------
    //
    //----------------------------------------
    void set_cookies(const std::map<std::string, std::string>& cookies) {
      cookie_jar_ = cookies;
    }
    
    //----------------------------------------
    //
    //----------------------------------------
    void clear_cookies() { 
      cookie_jar_.clear(); 
    }

private:
  std::string build_request(
    const std::string& method,
    const ParsedUrl& url,
    const HttpHeaders& headers,
    const std::string& body
  ) const;
    
  HttpConfig config_;
  std::unique_ptr<Remote> remote_;
  std::map<std::string, std::string> cookie_jar_;
};

}
