#include <HTTPClient.hpp>
#include "Helpers.hpp"

#include <sstream>
#include <algorithm>
#include <iomanip>
#include <regex>
#include <cctype>
#include <random>
#include <chrono>

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
//
//----------------------------------------
ParsedUrl parse_url(const std::string& url) {
  ParsedUrl result;
      
  // Regex for URL parsing
  std::regex url_regex(
    R"(^(https?):\/\/)"     // scheme
    R"(([^:\/\?#]+))"       // host
    R"((?::(\d+))?)"        // optional port
    R"(([^?\#]*))"          // path
    R"((?:\?([^#]*))?))"    // optional query
    R"(((?:#(.*))?)$)",     // optional fragment
    std::regex::icase
  );
      
  std::smatch matches;
  if(not std::regex_match(url, matches, url_regex)) {
    throw std::invalid_argument("Invalid URL format: " + url);
  }
      
  result.scheme = matches[1];
  std::transform(result.scheme.begin(), result.scheme.end(), result.scheme.begin(), ::tolower);
  result.host = matches[2];
      
  if(matches[3].matched) {
    result.port = static_cast<uint16_t>(std::stoi(matches[3]));
  }
      
  result.path = matches[4];
  if(matches[5].matched) result.query = matches[5];
  if(matches[6].matched) result.fragment = matches[6];
      
  return result;
}
  
//----------------------------------------
//
//----------------------------------------
HttpResponse parse_response(const std::string& response_data) {
  HttpResponse response;
  std::istringstream stream(response_data);
      
  // Parse status line
  std::string http_version;
  stream >> http_version >> response.status_code;
  std::getline(stream, response.status_message);
      
  // Trim status message
  response.status_message.erase(0, response.status_message.find_first_not_of(" \t"));
  response.status_message.erase(response.status_message.find_last_not_of("\r\n") + 1);
      
  // Parse headers
  std::string line;
  while(std::getline(stream, line) && line != "\r") {
    if(line.back() == '\r') line.pop_back();
    if(line.empty()) break;
          
    size_t colon = line.find(':');
    if(colon != std::string::npos) {
      std::string key = line.substr(0, colon);
      std::string value = line.substr(colon + 1);
              
      // Trim whitespace
      value.erase(0, value.find_first_not_of(" \t"));
      value.erase(value.find_last_not_of(" \t\r\n") + 1);
              
      // Convert header name to lowercase
      std::transform(key.begin(), key.end(), key.begin(), ::tolower);
      response.headers[key] = value;
    }
  }
      
  // Get body (rest of the stream)
  std::ostringstream body_stream;
  body_stream << stream.rdbuf();
  response.body = body_stream.str();
      
  return response;
}

//----------------------------------------
// Constructor
//----------------------------------------
HttpClient::HttpClient(const HttpConfig& config): config_(config), remote_(nullptr) {
}

//----------------------------------------
// Build HTTP request with browser-like headers
//----------------------------------------
std::string HttpClient::build_request(
  const std::string& method,
  const ParsedUrl& url,
  const HttpHeaders& headers,
  const std::string& body) const {
    
  std::ostringstream request;
  const auto& profile = get_profile_for_type(config_.browser_type);
    
  // Request line
  request << method << " " << url.get_path_with_query() << " HTTP/1.1\r\n";
    
  // Host header (required for HTTP/1.1)
  request << "Host: " << url.host;
  if((url.is_https() && url.get_port()     != 443) 
  || (not url.is_https() && url.get_port() != 80)) {
    request << ":" << url.get_port();
  }
  request << "\r\n";
    
  // Connection header
  if(headers.find("connection") == headers.end() 
  && headers.find("Connection") == headers.end()) {
    request << "Connection: keep-alive\r\n";
  }
    
  // Browser-like headers in realistic order
  if(headers.find("cache-control") == headers.end()
  && headers.find("Cache-Control") == headers.end()) {
    if(method == "GET") {
      request << "Cache-Control: max-age=0\r\n";
    }
  }
    
  // Sec-CH-UA headers (Chrome/Edge only)
  if(not profile.sec_ch_ua.empty() && config_.send_browser_headers) {
    if(headers.find("sec-ch-ua") == headers.end()) {
      request << "sec-ch-ua: " << profile.sec_ch_ua << "\r\n";
    }
        
    if(headers.find("sec-ch-ua-mobile") == headers.end()) {
      request << "sec-ch-ua-mobile: " << profile.sec_ch_ua_mobile << "\r\n";
    }

    if(headers.find("sec-ch-ua-platform") == headers.end()) {
      request << "sec-ch-ua-platform: " << profile.sec_ch_ua_platform << "\r\n";
    }
  }
    
  // Upgrade-Insecure-Requests
  if (config_.send_browser_headers && method == "GET"
  && headers.find("upgrade-insecure-requests") == headers.end()) {
    request << "Upgrade-Insecure-Requests: 1\r\n";
  }
    
  // User-Agent
  if(headers.find("user-agent") == headers.end()
  && headers.find("User-Agent") == headers.end()) {
    if(config_.send_browser_headers) {
      request << "User-Agent: " << profile.user_agent << "\r\n";
    } else {
      request << "User-Agent: " << config_.user_agent << "\r\n";
    }
  }
    
  // Accept
  if(headers.find("accept") == headers.end()
  && headers.find("Accept") == headers.end()) {
    if(config_.send_browser_headers) {
      request << "Accept: " << profile.accept << "\r\n";
    } else {
      request << "Accept: */*\r\n";
    }
  }
    
  // Sec-Fetch headers (Chrome/Edge only)
  if(profile.send_sec_fetch && config_.send_browser_headers) {
    if(headers.find("sec-fetch-site") == headers.end()) {
      request << "Sec-Fetch-Site: none\r\n";
      request << "Sec-Fetch-Mode: navigate\r\n";
      request << "Sec-Fetch-User: ?1\r\n";
      request << "Sec-Fetch-Dest: document\r\n";
    }
  }
    
  // Accept-Encoding
  if(headers.find("accept-encoding") == headers.end()
  && headers.find("Accept-Encoding") == headers.end()) {
    if(config_.send_browser_headers) {
      request << "Accept-Encoding: " << profile.accept_encoding << "\r\n";
    }
  }
    
  // Accept-Language
  if(headers.find("accept-language") == headers.end()
  && headers.find("Accept-Language") == headers.end()) {
    if(config_.send_browser_headers) {
      request << "Accept-Language: " << profile.accept_language << "\r\n";
    }
  }
    
  // Referer (if navigating from another page)
  if(config_.send_browser_headers && !config_.referer.empty() &&
    headers.find("referer") == headers.end() &&
    headers.find("Referer") == headers.end()) {
    request << "Referer: " << config_.referer << "\r\n";
  }
    
  // Content-Length for body
  if(not body.empty() && headers.find("content-length") == headers.end()
  && headers.find("Content-Length") == headers.end()) {
    request << "Content-Length: " << body.size() << "\r\n";
  }
    
  // Custom headers (maintain order and case sensitivity)
  for(const auto& [key, value] : headers) {
    request << key << ": " << value << "\r\n";
  }
    
  // DNT (Do Not Track) - some browsers send this
  if(config_.send_browser_headers && config_.send_dnt &&
    headers.find("dnt") == headers.end() &&
    headers.find("DNT") == headers.end()) {
    request << "DNT: 1\r\n";
  }
    
  // End of headers
  request << "\r\n";
    
  if(not body.empty()) {
    request << body;
  }
    
  return request.str();
}

//----------------------------------------
// Perform HTTP request with TLS fingerprinting
//----------------------------------------
HttpResponse HttpClient::request(
  const std::string& method,
  const std::string& url,
  const HttpHeaders& headers,
  const std::string& body) {
    
  auto parsed_url = parse_url(url);
  const auto& profile = get_profile_for_type(config_.browser_type);
    
  // Create connection with TLS configuration
  if(config_.proxy_url.empty()) {
    // Direct connection
    if (parsed_url.is_https()) {
      // Create custom SSL context for fingerprint emulation
      auto ssl_ctx = std::make_shared<asio::ssl::context>(asio::ssl::context::tls_client);
            
      // Set TLS version to match browser (TLS 1.2 or 1.3)
      SSL_CTX_set_min_proto_version(ssl_ctx->native_handle(), TLS1_2_VERSION);
      SSL_CTX_set_max_proto_version(ssl_ctx->native_handle(), TLS1_3_VERSION);
            
      // Set cipher suites to match browser fingerprint
      if(not profile.tls_cipher_suites.empty()) {
        std::ostringstream cipher_string;

        for(size_t i = 0; i < profile.tls_cipher_suites.size(); ++i) {
          if(i > 0) cipher_string << ":";
          cipher_string << profile.tls_cipher_suites[i];
        }
        SSL_CTX_set_cipher_list(ssl_ctx->native_handle(), cipher_string.str().c_str());
      }
            
      // Set supported curves to match browser
      if(not profile.tls_curves.empty()) {
        std::ostringstream curves_string;

        for (size_t i = 0; i < profile.tls_curves.size(); ++i) {
          if (i > 0) curves_string << ":";
            curves_string << profile.tls_curves[i];
        }

        SSL_CTX_set1_groups_list(ssl_ctx->native_handle(), curves_string.str().c_str());
      }
            
      // Enable ALPN (Application-Layer Protocol Negotiation) like browsers
      const unsigned char alpn[] = "\x02h2\x08http/1.1";
      SSL_CTX_set_alpn_protos(ssl_ctx->native_handle(), alpn, sizeof(alpn) - 1);
            
      // Set certificate verification
      if(config_.verify_ssl) {
        ssl_ctx->set_default_verify_paths();
        ssl_ctx->set_verify_mode(asio::ssl::verify_peer);
      } else {
        ssl_ctx->set_verify_mode(asio::ssl::verify_none);
      }
            
      remote_ = std::make_unique<Remote>(
        parsed_url.host, 
        parsed_url.get_port(),
        std::move(ssl_ctx)
      );
    } else {
      remote_ = std::make_unique<Remote>(
        parsed_url.host,
        parsed_url.get_port()
      );
    }
  } else {
    // Connection through proxy
    remote_ = std::make_unique<Remote>(
      parsed_url.host, parsed_url.get_port(),
      config_.proxy_url, parsed_url.is_https()
    );
  }
    
  // Add random delay to mimic human behavior
  if(config_.human_like_timing) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(50, 300);
    std::this_thread::sleep_for(std::chrono::milliseconds(dis(gen)));
  }
    
  // Build and send request
  std::string request_str = build_request(method, parsed_url, headers, body);
    
  if(config_.verbose) {
    std::cout << "=== Request ===\n" << request_str << "\n";
  }
    
  remote_->send(request_str);
    
  // Receive response (read until connection closes)
  std::string response_data = remote_->recvall();
    
  if(config_.verbose) {
    std::cout << "=== Response ===\n" << response_data << "\n";
  }
    
  remote_->close();
    
  // Parse response
  HttpResponse response = parse_response(response_data);
    
  // Store cookies automatically if enabled
  if(config_.auto_store_cookies) {
    auto new_cookies = get_cookies(response);
    cookie_jar_.insert(new_cookies.begin(), new_cookies.end());
  }
    
  // Handle redirects
  if(config_.follow_redirects && 
      (response.status_code == 301 || response.status_code == 302 ||
       response.status_code == 303 || response.status_code == 307 ||
       response.status_code == 308)) {
        
    if(config_.redirect_count >= config_.max_redirects) {
      throw std::runtime_error(
          "Too many redirects (max: " + std::to_string(config_.max_redirects) + ")"
      );
    }
        
    auto location_it = response.headers.find("location");

    if(location_it != response.headers.end()) {
        HttpConfig redirect_config = config_;
        redirect_config.redirect_count++;
        redirect_config.referer = url; // Set referer to current page
            
        HttpClient redirect_client(redirect_config);
        redirect_client.cookie_jar_ = cookie_jar_; // Copy cookies
            
        // For 303, always use GET
        std::string redirect_method = (response.status_code == 303) ? "GET" : method;
        std::string redirect_body = (response.status_code == 303) ? "" : body;
            
        // Resolve relative URLs
        std::string redirect_url = location_it->second;
      if(redirect_url[0] == '/') {
        redirect_url = parsed_url.scheme + "://" + parsed_url.host + 
          (parsed_url.port != 0 ? ":" + std::to_string(parsed_url.port) : "") + redirect_url;
      }
            
      return redirect_client.request(redirect_method, redirect_url, headers, redirect_body);
    }
  }
    
  return response;
}

//----------------------------------------
// GET request
//----------------------------------------
HttpResponse HttpClient::get(const std::string& url, const HttpHeaders& headers) {
  return request("GET", url, headers);
}

//----------------------------------------
// POST request
//----------------------------------------
HttpResponse HttpClient::post(const std::string& url, 
                              const std::string& body,
                              const HttpHeaders& headers) {
  return request("POST", url, headers, body);
}

//----------------------------------------
// POST with form data
//----------------------------------------
HttpResponse HttpClient::post_form(const std::string& url,
                                   const std::map<std::string, std::string>& form_data,
                                   const HttpHeaders& headers) {
  // Build form-encoded body
  std::ostringstream body;
  bool first = true;
    
  for(const auto& [key, value] : form_data) {
    if(not first) body << "&";
      body << url_encode(key) << "=" << url_encode(value);
      first = false;
  }
    
  // Add Content-Type header
  HttpHeaders modified_headers = headers;
  if(modified_headers.find("content-type") == modified_headers.end()) {
    modified_headers["Content-Type"] = "application/x-www-form-urlencoded";
  }
    
  return post(url, body.str(), modified_headers);
}

//----------------------------------------
// POST with JSON
//----------------------------------------
HttpResponse HttpClient::post_json(const std::string& url,
                                   const std::string& json,
                                   const HttpHeaders& headers) {
  HttpHeaders modified_headers = headers;
  if(modified_headers.find("content-type") == modified_headers.end()) {
    modified_headers["Content-Type"] = "application/json";
  }
    
  return post(url, json, modified_headers);
}

//----------------------------------------
// PUT request
//----------------------------------------
HttpResponse HttpClient::put(const std::string& url,
                             const std::string& body,
                             const HttpHeaders& headers) {
  return request("PUT", url, headers, body);
}

//----------------------------------------
// DELETE request
//----------------------------------------
HttpResponse HttpClient::del(const std::string& url, const HttpHeaders& headers) {
  return request("DELETE", url, headers);
}

//----------------------------------------
// HEAD request
//----------------------------------------
HttpResponse HttpClient::head(const std::string& url, const HttpHeaders& headers) {
  return request("HEAD", url, headers);
}

//----------------------------------------
// PATCH request
//----------------------------------------
HttpResponse HttpClient::patch(const std::string& url,
                               const std::string& body,
                               const HttpHeaders& headers) {
  return request("PATCH", url, headers, body);
}

//----------------------------------------
// OPTIONS request
//----------------------------------------
HttpResponse HttpClient::options(const std::string& url, const HttpHeaders& headers) {
  return request("OPTIONS", url, headers);
}

//----------------------------------------
// Download file
//----------------------------------------
bool HttpClient::download(const std::string& url, const std::string& output_path) {
  try {
    auto response = get(url);
        
    if(response.status_code != 200) {
      std::cerr << "Download failed: HTTP " << response.status_code << "\n";
      return false;
    }
        
    std::ofstream file(output_path, std::ios::binary);
    if(not file) {
      std::cerr << "Cannot open file for writing: " << output_path << "\n";
      return false;
    }
        
    file.write(response.body.data(), response.body.size());
    return file.good();
        
    } catch (const std::exception& e) {
        std::cerr << "Download error: " << e.what() << "\n";
        return false;
  }
}

//----------------------------------------
// Get cookies from response
//----------------------------------------
std::map<std::string, std::string> HttpClient::get_cookies(const HttpResponse& response) {
  std::map<std::string, std::string> cookies;
    
  // Look for Set-Cookie headers (there can be multiple)
  for(const auto& [key, value] : response.headers) {
    if(key == "set-cookie") {
      // Parse cookie: name=value; other-attributes
      size_t eq_pos = value.find('=');
      size_t semi_pos = value.find(';');
            
      if(eq_pos != std::string::npos) {
        std::string name = value.substr(0, eq_pos);
        std::string val = value.substr(eq_pos + 1, 
          semi_pos == std::string::npos ? std::string::npos : semi_pos - eq_pos - 1
        );
                
        // Trim whitespace
        name.erase(0, name.find_first_not_of(" \t"));
        name.erase(name.find_last_not_of(" \t") + 1);
        val.erase(0, val.find_first_not_of(" \t"));
        val.erase(val.find_last_not_of(" \t") + 1);
        cookies[name] = val;
      }
    }
  }
    
  return cookies;
}

//----------------------------------------
// Set cookies for request
//----------------------------------------
HttpHeaders HttpClient::with_cookies(const HttpHeaders& headers, 
  const std::map<std::string, std::string>& cookies) {
    
  HttpHeaders modified_headers = headers;
    
  if(not cookies.empty()) {
    std::ostringstream cookie_header;
    bool first = true;
        
    for(const auto& [name, value] : cookies) {
      if(not first) cookie_header << "; ";
        cookie_header << name << "=" << value;
        first = false;
    }
        
    modified_headers["Cookie"] = cookie_header.str();
  }
    
  return modified_headers;
}

} 
