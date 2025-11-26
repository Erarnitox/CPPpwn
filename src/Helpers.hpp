#pragma once

#include <atomic>
#include <Stream.hpp>
#include <iostream>
#include <ostream>
#include <iomanip>
#include <string>

//----------------------------------------
//
//----------------------------------------
static inline void copy_stdin_to_stream(cpppwn::Stream* stream, std::atomic<bool>& running) noexcept {
    std::string line;
    while (running && std::getline(std::cin, line)) {
        stream->sendline(line);
    }
    running = false;
}

//----------------------------------------
//
//----------------------------------------
static inline void copy_stream_to_stdout(cpppwn::Stream* stream, std::atomic<bool>& running) noexcept {
    try {
        while (running && stream->is_alive()) {
            std::string data = stream->recvline();
            if (!data.empty()) {
                std::cout << data << std::flush;
            }
        }
    } catch (...) {
        // Silence any read errors on close
    }
    running = false;
}

//----------------------------------------
//
//----------------------------------------
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
