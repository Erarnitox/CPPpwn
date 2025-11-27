#pragma once

#include <atomic>
#include <Stream.hpp>
#include <print>
#include <ostream>
#include <iostream>
#include <iomanip>
#include <string>
#include <map>
#include <filesystem>

#include <asio.hpp>

namespace fs = std::filesystem;

//----------------------------------------
//
//----------------------------------------
static inline void copy_stdin_to_stream(cpppwn::Stream* stream, std::atomic<bool>& running) noexcept {
  std::string line;

  while(running && std::getline(std::cin, line)) {
    stream->sendline(line);
  }
  running = false;
}

//----------------------------------------
//
//----------------------------------------
static inline void copy_stream_to_stdout(cpppwn::Stream* stream, std::atomic<bool>& running) noexcept {
  try {
    while(running && stream->is_alive()) {
      std::string data = stream->recvline();
      if(not data.empty()) {
        std::print("{}", data); 
      }
    }
  } catch (...) {
  }
  running = false;
}

//----------------------------------------
//
//----------------------------------------
inline constexpr
std::string base64_encode(const std::string& input) {
  constexpr char base64_chars[]{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" };
  
  std::string result;
  int val{ 0 };
  int bits = -6;
        
  for(unsigned char c : input) {
    val = (val << 8) + c;
    bits += 8;
            
    while(bits >= 0) {
      result.push_back(base64_chars[(val >> bits) & 0x3F]);
      bits -= 6;
    }
  }
        
  if(bits > -6) {
    result.push_back(base64_chars[((val << 8) >> (bits + 8)) & 0x3F]);
  }
        
  while(result.size() % 4) {
    result.push_back('=');
  }
        
  return result;
}

//----------------------------------------
//
//----------------------------------------
inline constexpr
std::string url_encode(const std::string& value) {
  std::ostringstream escaped;
  escaped.fill('0');
  escaped << std::hex;
        
  for(char c : value) {
    if(std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.' || c == '~') {
        escaped << c;
    } else {
        escaped << '%' << std::setw(2) << static_cast<int>(static_cast<unsigned char>(c));
    }
  }
  return escaped.str();
}

//----------------------------------------
//
//----------------------------------------
inline constexpr
std::string url_decode(const std::string& str) {
  std::string result;
  result.reserve(str.size());
        
  for(size_t i = 0; i < str.size(); ++i) {
    if(str[i] == '%' && i + 2 < str.size()) {
      int value;
      std::istringstream iss(str.substr(i + 1, 2));
      if(iss >> std::hex >> value) {
        result += static_cast<char>(value);
        i += 2;
      } else {
        result += str[i];
      }
    } else if(str[i] == '+') {
      result += ' ';
    } else {
      result += str[i];
    }
  }
        
  return result;
}
//----------------------------------------
//
//----------------------------------------
inline constexpr
std::map<std::string, std::string> parse_query_string(const std::string& query) {
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
inline constexpr
std::map<std::string, std::string> parse_cookies(const std::string& cookie_header) {
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
inline constexpr
std::string get_mime_type(const std::string& path) {
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
      
  fs::path file_path(path);
  std::string ext = file_path.extension().string();
  std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
      
  auto it = mime_types.find(ext);
  return (it != mime_types.end()) ? it->second : "application/octet-stream";
}
  
//----------------------------------------
//
//----------------------------------------
inline constexpr
std::string get_http_date() {
  auto now = std::chrono::system_clock::now();
  std::time_t now_c = std::chrono::system_clock::to_time_t(now);
  std::tm gmt;

  gmtime_r(&now_c, &gmt);
      
  char buffer[100];
  std::strftime(buffer, sizeof(buffer), "%a, %d %b %Y %H:%M:%S GMT", &gmt);
  return std::string(buffer);
}

