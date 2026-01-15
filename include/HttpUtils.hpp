#pragma once

#include "Utils.hpp"

struct HttpRequest;
struct HttpResponse;
struct CookieOptions;

using HttpHeaders = std::map<std::string, std::string>;
using RouteHandler = std::function<HttpResponse(const HttpRequest&)>;
using Middleware = std::function<bool(const HttpRequest&, HttpResponse&)>;

//----------------------------------------
//
//----------------------------------------
inline std::map<std::string, std::string> parse_query_string(const std::string& query) {
  std::map<std::string, std::string> params;

  std::istringstream stream(query);
  std::string pair;

  while(std::getline(stream, pair, '&')) {
    size_t eq = pair.find('=');
    if(eq != std::string::npos) {
      std::string key = url_decode(pair.substr(0, eq));
      std::string value = url_decode(pair.substr(eq + 1));
      params[key] = value;
    } else {
      params[url_decode(pair)] = "";
    }
  }
  return params;
}

//----------------------------------------
//
//----------------------------------------
inline std::map<std::string, std::string> parse_cookies(const std::string& cookie_header) {
  std::map<std::string, std::string> cookies;

  std::istringstream stream(cookie_header);
  std::string pair;

  while(std::getline(stream, pair, ';')) {
    pair.erase(0, pair.find_first_not_of(" \t"));
    pair.erase(pair.find_last_not_of(" \t") + 1);

    size_t eq = pair.find('=');
    if(eq != std::string::npos) {
      std::string key = pair.substr(0, eq);
      std::string value = pair.substr(eq + 1);
      cookies[key] = value;
    }
  }
  return cookies;
}

//----------------------------------------
//
//----------------------------------------
inline std::string get_mime_type(const std::string& path) {
  static const std::map<std::string, std::string> mime_types = {
    {".html", "text/html"},
    {".htm", "text/html"},
    {".css", "text/css"},
    {".js", "application/javascript"},
    {".json", "application/json"},
    {".xml", "application/xml"},
    {".txt", "text/plain"},
    {".jpg", "image/jpeg"},
    {".jpeg", "image/jpeg"},
    {".png", "image/png"},
    {".gif", "image/gif"},
    {".svg", "image/svg+xml"},
    {".ico", "image/x-icon"},
    {".pdf", "application/pdf"},
    {".zip", "application/zip"},
    {".mp3", "audio/mpeg"},
    {".mp4", "video/mp4"},
    {".woff", "font/woff"},
    {".woff2", "font/woff2"},
    {".ttf", "font/ttf"},
    {".webp", "image/webp"}
  };

  std::filesystem::path file_path(path);
  std::string ext = file_path.extension().string();
  std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

  auto it = mime_types.find(ext);
  return (it != mime_types.end()) ? it->second : "application/octet-stream";
}

//----------------------------------------
//
//----------------------------------------
inline std::string get_http_date() {
  auto now = std::chrono::system_clock::now();
  std::time_t now_c = std::chrono::system_clock::to_time_t(now);
  std::tm gmt;

  gmtime_r(&now_c, &gmt);

  char buffer[100];
  std::strftime(buffer, sizeof(buffer), "%a, %d %b %Y %H:%M:%S GMT", &gmt);
  return std::string(buffer);
}

//----------------------------------------
//
//----------------------------------------
struct HttpRequest {
  std::string method;                              // HTTP method (GET, POST, etc.)
  std::string path;                                // Request path (e.g., "/api/users")
  std::string http_version;                        // HTTP version (e.g., "HTTP/1.1")
  std::map<std::string, std::string> headers;      // Request headers (lowercase keys)
  std::map<std::string, std::string> query_params; // Query parameters
  std::map<std::string, std::string> cookies;      // Parsed cookies
  std::map<std::string, std::string> form_data;    // Parsed form data
  std::string body;                                // Raw request body

  [[nodiscard]] std::string get_header(const std::string& name) const;

  [[nodiscard]] bool has_header(const std::string& name) const;

  [[nodiscard]] std::string get_cookie(const std::string& name) const;

  [[nodiscard]] std::string get_param(const std::string& name) const;
};

//----------------------------------------
//
//----------------------------------------
struct CookieOptions {
  int max_age = 0;                // Max age in seconds (0 = session cookie)
  std::string path = "/";         // Cookie path
  std::string domain;             // Cookie domain
  bool secure = false;            // Secure flag (HTTPS only)
  bool http_only = true;          // HttpOnly flag (no JavaScript access)
  std::string same_site = "Lax";  // SameSite attribute (Strict, Lax, None)
};

//----------------------------------------
//
//----------------------------------------
struct HttpResponse {
  int status_code = 0;
  std::string status_message;
  HttpHeaders headers;
  std::string body;
  std::vector<std::string> cookies;

  explicit HttpResponse(int code = 200);

  [[nodiscard]] bool ok() const noexcept;

  [[nodiscard]] std::string get_header(const std::string& key) const;

  [[nodiscard]] bool has_header(const std::string& key) const;

  HttpResponse& set_status(int code);

  HttpResponse& set_header(const std::string& name, const std::string& value);

  HttpResponse& set_cookie(const std::string& name, const std::string& value,
                           const CookieOptions& options = {});

  HttpResponse& set_body(const std::string& content);

  HttpResponse& set_json(const std::string& json);

  HttpResponse& set_html(const std::string& html);

  HttpResponse& redirect(const std::string& location, int code = 302);

  [[nodiscard]] std::string to_string() const;

  static std::string get_status_message(int code);
};


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
// HttpConfig - Configuration for HTTP client
//----------------------------------------
struct HttpConfig {
  std::string user_agent = "cpppwn-http/1.0";      // User-Agent header (if not emulating browser)
  bool follow_redirects = true;                    // Follow HTTP redirects
  size_t max_redirects = 10;                       // Maximum number of redirects
  bool verify_ssl = false;                         // Verify SSL certificates
  bool verbose = false;                            // Print request/response for debugging
  std::string proxy;                               // Changed from proxy_url to proxy (libcurl uses this)
  long timeout_ms = 30000;                         // Timeout in milliseconds (added for libcurl)
  size_t redirect_count = 0;                       // Internal redirect counter
  BrowserType browser_type = BrowserType::Chrome;  // Browser to emulate
  bool send_browser_headers = true;                // Send realistic browser headers
  bool human_like_timing = false;                  // Add random delays to mimic humans
  bool send_dnt = false;                           // Send Do-Not-Track header
  std::string referer;                             // Referer header for navigation
  bool auto_store_cookies = true;                  // Automatically store cookies
  std::map<std::string, std::string> cookies;      // Cookie storage (added)

  HttpConfig() = default;

  explicit HttpConfig(std::string ua)
    : user_agent(std::move(ua)), send_browser_headers(false) {}

  explicit HttpConfig(BrowserType browser)
    : browser_type(browser), send_browser_headers(true) {}
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
