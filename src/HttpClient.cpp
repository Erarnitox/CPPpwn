#include <HttpClient.hpp>
#include "Helpers.hpp"
#include <algorithm>
#include <memory>
#include <stdexcept>

namespace cpppwn {

//----------------------------------------
// Browser profiles for realistic TLS fingerprinting
//----------------------------------------
struct BrowserProfile {
  std::string user_agent;
  std::string accept;
  std::string accept_language;
  std::string accept_encoding;
  std::vector<std::string> tls_cipher_suites;
  std::vector<std::string> tls_extensions;
  std::vector<std::string> tls_curves;
  std::string sec_ch_ua;
  std::string sec_ch_ua_mobile;
  std::string sec_ch_ua_platform;
  bool send_sec_fetch;
};
  
//----------------------------------------
//
//----------------------------------------
BrowserProfile get_chrome_profile() {
  return {
    .user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    .accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    .accept_language = "en-US,en;q=0.9",
    .accept_encoding = "gzip, deflate, br",
    .tls_cipher_suites = {
      "TLS_AES_128_GCM_SHA256",
      "TLS_AES_256_GCM_SHA384",
      "TLS_CHACHA20_POLY1305_SHA256",
      "ECDHE-ECDSA-AES128-GCM-SHA256",
      "ECDHE-RSA-AES128-GCM-SHA256",
      "ECDHE-ECDSA-AES256-GCM-SHA384",
      "ECDHE-RSA-AES256-GCM-SHA384"
    },
    .tls_extensions = {
      "server_name", "extended_master_secret", "renegotiation_info",
      "supported_groups", "ec_point_formats", "session_ticket",
      "application_layer_protocol_negotiation", "status_request",
      "signature_algorithms", "signed_certificate_timestamp",
      "key_share", "psk_key_exchange_modes", "supported_versions",
      "compress_certificate", "application_settings"
    },
    .tls_curves = {
      "X25519", "secp256r1", "secp384r1"
    },
    .sec_ch_ua = "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"",
    .sec_ch_ua_mobile = "?0",
    .sec_ch_ua_platform = "\"Windows\"",
    .send_sec_fetch = true
  };
}
  
//----------------------------------------
//
//----------------------------------------
BrowserProfile get_firefox_profile() {
  return {
    .user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) "
                  "Gecko/20100101 Firefox/121.0",
    .accept = "text/html,application/xhtml+xml,application/xml;q=0.9,"
              "image/avif,image/webp,*/*;q=0.8",
    .accept_language = "en-US,en;q=0.5",
    .accept_encoding = "gzip, deflate, br",
    .tls_cipher_suites = {
      "TLS_AES_128_GCM_SHA256",
      "TLS_CHACHA20_POLY1305_SHA256",
      "TLS_AES_256_GCM_SHA384",
      "ECDHE-ECDSA-AES128-GCM-SHA256",
      "ECDHE-RSA-AES128-GCM-SHA256",
      "ECDHE-ECDSA-CHACHA20-POLY1305",
      "ECDHE-RSA-CHACHA20-POLY1305"
    },
    .tls_extensions = {
      "server_name", "extended_master_secret", "renegotiation_info",
      "supported_groups", "ec_point_formats", "session_ticket",
      "application_layer_protocol_negotiation", "status_request",
      "signature_algorithms", "key_share", "supported_versions",
      "psk_key_exchange_modes", "record_size_limit"
     },
     .tls_curves = {"X25519", "secp256r1", "secp384r1", "secp521r1"},
     .sec_ch_ua = "",
     .sec_ch_ua_mobile = "",
     .sec_ch_ua_platform = "",
     .send_sec_fetch = false
  };
}
  
//----------------------------------------
//
//----------------------------------------
BrowserProfile get_safari_profile() {
  return {
    .user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                  "AppleWebKit/605.1.15 (KHTML, like Gecko) "
                  "Version/17.1 Safari/605.1.15",
    .accept = "text/html,application/xhtml+xml,application/xml;q=0.9,"
              "*/*;q=0.8",
    .accept_language = "en-US,en;q=0.9",
    .accept_encoding = "gzip, deflate, br",
    .tls_cipher_suites = {
      "TLS_AES_128_GCM_SHA256",
      "TLS_AES_256_GCM_SHA384",
      "TLS_CHACHA20_POLY1305_SHA256",
      "ECDHE-ECDSA-AES256-GCM-SHA384",
      "ECDHE-ECDSA-AES128-GCM-SHA256",
      "ECDHE-RSA-AES256-GCM-SHA384",
      "ECDHE-RSA-AES128-GCM-SHA256"
    },
    .tls_extensions = {
      "server_name", "extended_master_secret", "renegotiation_info",
      "supported_groups", "ec_point_formats", "application_layer_protocol_negotiation",
      "status_request", "signature_algorithms", "signed_certificate_timestamp",
      "key_share", "psk_key_exchange_modes", "supported_versions"
    },
    .tls_curves = {"X25519", "secp256r1", "secp384r1", "secp521r1"},
    .sec_ch_ua = "",
    .sec_ch_ua_mobile = "",
    .sec_ch_ua_platform = "",
    .send_sec_fetch = false
  };
}
  
//----------------------------------------
//
//----------------------------------------
BrowserProfile get_edge_profile() {
  return {
    .user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    .accept = "text/html,application/xhtml+xml,application/xml;q=0.9,"
              "image/avif,image/webp,image/apng,*/*;q=0.8,"
              "application/signed-exchange;v=b3;q=0.7",
    .accept_language = "en-US,en;q=0.9",
    .accept_encoding = "gzip, deflate, br",
    .tls_cipher_suites = {
      "TLS_AES_128_GCM_SHA256",
      "TLS_AES_256_GCM_SHA384",
      "TLS_CHACHA20_POLY1305_SHA256",
      "ECDHE-ECDSA-AES128-GCM-SHA256",
      "ECDHE-RSA-AES128-GCM-SHA256",
      "ECDHE-ECDSA-AES256-GCM-SHA384",
      "ECDHE-RSA-AES256-GCM-SHA384"
    },
    .tls_extensions = {
      "server_name", "extended_master_secret", "renegotiation_info",
      "supported_groups", "ec_point_formats", "session_ticket",
      "application_layer_protocol_negotiation", "status_request",
      "signature_algorithms", "signed_certificate_timestamp",
      "key_share", "psk_key_exchange_modes", "supported_versions",
      "compress_certificate", "application_settings"
    },
    .tls_curves = {"X25519", "secp256r1", "secp384r1"},
    .sec_ch_ua = "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Microsoft Edge\";v=\"120\"",
    .sec_ch_ua_mobile = "?0",
    .sec_ch_ua_platform = "\"Windows\"",
    .send_sec_fetch = true
  };
}
  
//----------------------------------------
//
//----------------------------------------
BrowserProfile get_profile_for_type(BrowserType type) {
  switch (type) {
    case BrowserType::Chrome: return get_chrome_profile();
    case BrowserType::Firefox: return get_firefox_profile();
    case BrowserType::Safari: return get_safari_profile();
    case BrowserType::Edge: return get_edge_profile();
    default: return get_chrome_profile();
  }
}

//----------------------------------------
// Callback for writing response data
//----------------------------------------
static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
  size_t total_size = size * nmemb;
  std::string* response = static_cast<std::string*>(userp);
  response->append(static_cast<char*>(contents), total_size);
  return total_size;
}

//----------------------------------------
// Callback for reading request body
//----------------------------------------
static size_t read_callback(char* buffer, size_t size, size_t nitems, void* userp) {
  std::string* body = static_cast<std::string*>(userp);
  size_t buffer_size = size * nitems;
  size_t to_copy = std::min(body->size(), buffer_size);
  
  std::memcpy(buffer, body->data(), to_copy);
  body->erase(0, to_copy);
  
  return to_copy;
}

//----------------------------------------
// Callback for header parsing
//----------------------------------------
static size_t header_callback(char* buffer, size_t size, size_t nitems, void* userp) {
  size_t total_size = size * nitems;
  std::string header(buffer, total_size);
  HttpHeaders* headers = static_cast<HttpHeaders*>(userp);
  
  // Find colon separator
  size_t colon = header.find(':');
  if (colon != std::string::npos) {
    std::string key = header.substr(0, colon);
    std::string value = header.substr(colon + 1);
    
    // Trim whitespace
    value.erase(0, value.find_first_not_of(" \t"));
    value.erase(value.find_last_not_of(" \t\r\n") + 1);
    
    // Convert to lowercase
    std::transform(key.begin(), key.end(), key.begin(), ::tolower);
    (*headers)[key] = value;
  }
  
  return total_size;
}

//----------------------------------------
// Constructor
//----------------------------------------
HttpClient::HttpClient(const HttpConfig& config) 
  : config_(config), curl_handle_(std::make_unique<CurlHandle>()) {
  
  // Initialize curl globally (thread-safe after first call)
  static bool curl_initialized = false;
  if (not curl_initialized) {
    curl_global_init(CURL_GLOBAL_ALL);
    curl_initialized = true;
  }
}

//----------------------------------------
// Perform HTTP request
//----------------------------------------
HttpResponse HttpClient::request(
  const std::string& method,
  const std::string& url,
  const HttpHeaders& headers,
  const std::string& body) {
  
  CurlHandle curl;
  CURL* handle = curl.get();
  
  // Get browser profile
  BrowserProfile profile = get_profile_for_type(config_.browser_type);
  
  // Response data
  std::string response_body;
  HttpHeaders response_headers;
  
  // Set URL
  curl_easy_setopt(handle, CURLOPT_URL, url.c_str());
  
  // Enable verbose output for debugging if configured
  if (config_.verbose) {
    curl_easy_setopt(handle, CURLOPT_VERBOSE, 1L);
  }
  
  // Set method
  if (method == "GET") {
    curl_easy_setopt(handle, CURLOPT_HTTPGET, 1L);
  } else if (method == "POST") {
    curl_easy_setopt(handle, CURLOPT_POST, 1L);
  } else if (method == "PUT") {
    curl_easy_setopt(handle, CURLOPT_CUSTOMREQUEST, "PUT");
  } else if (method == "DELETE") {
    curl_easy_setopt(handle, CURLOPT_CUSTOMREQUEST, "DELETE");
  } else if (method == "HEAD") {
    curl_easy_setopt(handle, CURLOPT_NOBODY, 1L);
  } else if (method == "PATCH") {
    curl_easy_setopt(handle, CURLOPT_CUSTOMREQUEST, "PATCH");
  } else {
    curl_easy_setopt(handle, CURLOPT_CUSTOMREQUEST, method.c_str());
  }
  
  // Build headers
  CurlHeaders curl_headers;
  
  // Add browser profile headers
  curl_headers.append("User-Agent: " + profile.user_agent);
  curl_headers.append("Accept: " + profile.accept);
  curl_headers.append("Accept-Language: " + profile.accept_language);
  
  // Only add Accept-Encoding if not manually set
  bool has_accept_encoding = false;
  for (const auto& [key, value] : headers) {
    std::string lower_key = key;
    std::transform(lower_key.begin(), lower_key.end(), lower_key.begin(), ::tolower);
    if (lower_key == "accept-encoding") {
      has_accept_encoding = true;
      break;
    }
  }
  
  if (not has_accept_encoding && not profile.accept_encoding.empty()) {
    curl_headers.append("Accept-Encoding: " + profile.accept_encoding);
  }
  
  if (not profile.sec_ch_ua.empty()) {
    curl_headers.append("Sec-CH-UA: " + profile.sec_ch_ua);
    curl_headers.append("Sec-CH-UA-Mobile: " + profile.sec_ch_ua_mobile);
    curl_headers.append("Sec-CH-UA-Platform: " + profile.sec_ch_ua_platform);
  }
  
  if (profile.send_sec_fetch) {
    curl_headers.append("Sec-Fetch-Site: none");
    curl_headers.append("Sec-Fetch-Mode: navigate");
    curl_headers.append("Sec-Fetch-User: ?1");
    curl_headers.append("Sec-Fetch-Dest: document");
  }
  
  // Add custom headers (override defaults)
  for (const auto& [key, value] : headers) {
    curl_headers.append(key + ": " + value);
  }
  
  // Add cookies if configured
  if (not config_.cookies.empty()) {
    std::string cookie_header = "Cookie: ";
    bool first = true;
    for (const auto& [key, value] : config_.cookies) {
      if (not first) cookie_header += "; ";
      cookie_header += key + "=" + value;
      first = false;
    }
    curl_headers.append(cookie_header);
  }
  
  curl_easy_setopt(handle, CURLOPT_HTTPHEADER, curl_headers.get());
  
  // Set request body
  std::string body_copy = body; // Need mutable copy for read callback
  if (not body.empty() && (method == "POST" || method == "PUT" || method == "PATCH")) {
    curl_easy_setopt(handle, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, body.size());
  }
  
  // Set callbacks
  curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(handle, CURLOPT_WRITEDATA, &response_body);
  curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, header_callback);
  curl_easy_setopt(handle, CURLOPT_HEADERDATA, &response_headers);
  
  // Set timeout
  if (config_.timeout_ms > 0) {
    curl_easy_setopt(handle, CURLOPT_TIMEOUT_MS, config_.timeout_ms);
  }
  
  // Set connection timeout (separate from overall timeout)
  curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, 30L);
  
  // SSL/TLS settings
  if (config_.verify_ssl) {
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 2L);
  } else {
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 0L);
  }
  
  // Follow redirects
  if (config_.follow_redirects) {
    curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(handle, CURLOPT_MAXREDIRS, config_.max_redirects);
  }
  
  // Proxy settings
  if (not config_.proxy.empty()) {
    curl_easy_setopt(handle, CURLOPT_PROXY, config_.proxy.c_str());
  }
  
  // Enable automatic decompression for all supported encodings
  curl_easy_setopt(handle, CURLOPT_ACCEPT_ENCODING, "");
  
  // HTTP version negotiation - let curl choose the best version
  curl_easy_setopt(handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
  
  // Enable TCP keep-alive
  curl_easy_setopt(handle, CURLOPT_TCP_KEEPALIVE, 1L);
  
  // Handle transfer encoding issues more gracefully
  curl_easy_setopt(handle, CURLOPT_HTTP_TRANSFER_DECODING, 1L);
  curl_easy_setopt(handle, CURLOPT_HTTP_CONTENT_DECODING, 1L);
  
  // Set buffer size for better performance
  curl_easy_setopt(handle, CURLOPT_BUFFERSIZE, 102400L);
  
  // Fail on HTTP errors (4xx, 5xx) - optional, comment out if not desired
  // curl_easy_setopt(handle, CURLOPT_FAILONERROR, 0L);
  
  // Perform request
  CURLcode res = curl_easy_perform(handle);
  
  // Get response code first (available even if request failed)
  long response_code = 0;
  curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &response_code);
  
  // Check for errors - but be more lenient with certain errors
  if (res != CURLE_OK) {
    // Some errors are acceptable depending on context
    bool is_fatal = true;
    
    switch (res) {
      case CURLE_PARTIAL_FILE:
        // Partial transfer - we might have useful data
        if (response_code >= 200 && response_code < 300) {
          is_fatal = false;
        }
        break;
      
      case CURLE_HTTP_RETURNED_ERROR:
        // HTTP error codes (4xx, 5xx) - not fatal, we want the response
        is_fatal = false;
        break;
        
      case CURLE_WRITE_ERROR:
        // Write callback returned wrong amount - might still have data
        if (not response_body.empty()) {
          is_fatal = false;
        }
        break;
        
      default:
        is_fatal = true;
        break;
    }
    
    if (is_fatal) {
      throw std::runtime_error("CURL request failed: " + 
                             std::string(curl_easy_strerror(res)));
    }
  }
  
  // Build response
  HttpResponse response;
  response.status_code = static_cast<int>(response_code);
  response.headers = std::move(response_headers);
  response.body = std::move(response_body);
  
  // Set status message based on code
  if (response.status_code >= 200 && response.status_code < 300) {
    response.status_message = "OK";
  } else if (response.status_code >= 300 && response.status_code < 400) {
    response.status_message = "Redirect";
  } else if (response.status_code >= 400 && response.status_code < 500) {
    response.status_message = "Client Error";
  } else if (response.status_code >= 500) {
    response.status_message = "Server Error";
  }
  
  return response;
}

//----------------------------------------
// Convenience methods
//----------------------------------------
HttpResponse HttpClient::get(const std::string& url, const HttpHeaders& headers) {
  return request("GET", url, headers, "");
}

HttpResponse HttpClient::post(const std::string& url, const std::string& body, 
                              const HttpHeaders& headers) {
  return request("POST", url, headers, body);
}

HttpResponse HttpClient::put(const std::string& url, const std::string& body,
                             const HttpHeaders& headers) {
  return request("PUT", url, headers, body);
}

HttpResponse HttpClient::del(const std::string& url, const HttpHeaders& headers) {
  return request("DELETE", url, headers, "");
}

HttpResponse HttpClient::patch(const std::string& url, const std::string& body,
                               const HttpHeaders& headers) {
  return request("PATCH", url, headers, body);
}

HttpResponse HttpClient::head(const std::string& url, const HttpHeaders& headers) {
  return request("HEAD", url, headers, "");
}

HttpResponse HttpClient::options(const std::string& url, const HttpHeaders& headers) {
  return request("OPTIONS", url, headers, "");
}

//----------------------------------------
// POST form data (URL-encoded)
//----------------------------------------
HttpResponse HttpClient::post_form(
  const std::string& url,
  const std::map<std::string, std::string>& form_data,
  const HttpHeaders& headers) {
  
  // URL-encode form data
  std::string body;
  bool first = true;
  
  CurlHandle curl;
  for (const auto& [key, value] : form_data) {
    if (not first) body += "&";
    
    // URL encode key and value
    char* encoded_key = curl_easy_escape(curl.get(), key.c_str(), key.length());
    char* encoded_value = curl_easy_escape(curl.get(), value.c_str(), value.length());
    
    body += encoded_key;
    body += "=";
    body += encoded_value;
    
    curl_free(encoded_key);
    curl_free(encoded_value);
    
    first = false;
  }
  
  // Add Content-Type header
  HttpHeaders form_headers = headers;
  form_headers["Content-Type"] = "application/x-www-form-urlencoded";
  
  return post(url, body, form_headers);
}

//----------------------------------------
// POST JSON data
//----------------------------------------
HttpResponse HttpClient::post_json(
  const std::string& url,
  const std::string& json,
  const HttpHeaders& headers) {
  
  HttpHeaders json_headers = headers;
  json_headers["Content-Type"] = "application/json";
  
  return post(url, json, json_headers);
}

//----------------------------------------
// Download file to disk
//----------------------------------------
bool HttpClient::download(const std::string& url, const std::string& output_path) {
  try {
    CurlHandle curl;
    CURL* handle = curl.get();
    
    // Open file for writing
    FILE* fp = fopen(output_path.c_str(), "wb");
    if (!fp) {
      return false;
    }
    
    // Set URL
    curl_easy_setopt(handle, CURLOPT_URL, url.c_str());
    
    // Write to file
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, fp);
    
    // Follow redirects
    if (config_.follow_redirects) {
      curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1L);
    }
    
    // SSL settings
    if (config_.verify_ssl) {
      curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 1L);
      curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 2L);
    } else {
      curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 0L);
      curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 0L);
    }
    
    // Timeout
    if (config_.timeout_ms > 0) {
      curl_easy_setopt(handle, CURLOPT_TIMEOUT_MS, config_.timeout_ms);
    }
    
    // Perform download
    CURLcode res = curl_easy_perform(handle);
    
    fclose(fp);
    
    return (res == CURLE_OK);
  } catch (...) {
    return false;
  }
}

//----------------------------------------
// Extract cookies from response
//----------------------------------------
std::map<std::string, std::string> HttpClient::get_cookies(const HttpResponse& response) {
  std::map<std::string, std::string> cookies;
  
  // Look for Set-Cookie headers
  for (const auto& [key, value] : response.headers) {
    if (key == "set-cookie") {
      // Parse cookie: name=value; other-attributes
      size_t eq = value.find('=');
      size_t semi = value.find(';');
      
      if (eq != std::string::npos) {
        std::string name = value.substr(0, eq);
        std::string cookie_value;
        
        if (semi != std::string::npos) {
          cookie_value = value.substr(eq + 1, semi - eq - 1);
        } else {
          cookie_value = value.substr(eq + 1);
        }
        
        cookies[name] = cookie_value;
      }
    }
  }
  
  return cookies;
}

//----------------------------------------
// Merge cookies into headers
//----------------------------------------
HttpHeaders HttpClient::with_cookies(
  const HttpHeaders& headers,
  const std::map<std::string, std::string>& cookies) {
  
  HttpHeaders result = headers;
  
  if (!cookies.empty()) {
    std::string cookie_header = "Cookie: ";
    bool first = true;
    
    for (const auto& [key, value] : cookies) {
      if (!first) cookie_header += "; ";
      cookie_header += key + "=" + value;
      first = false;
    }
    
    result["Cookie"] = cookie_header;
  }
  
  return result;
}

//----------------------------------------
// Set custom header
//----------------------------------------
void HttpClient::set_header(const std::string& key, const std::string& value) {
  default_headers_[key] = value;
}

//----------------------------------------
// Set cookie
//----------------------------------------
void HttpClient::set_cookie(const std::string& key, const std::string& value) {
  config_.cookies[key] = value;
}

//----------------------------------------
// Clear cookies
//----------------------------------------
void HttpClient::clear_cookies() {
  config_.cookies.clear();
}

} // namespace cpppwn