#pragma once

#include <ios>
#include <string>
#include <map>
#include <algorithm>
#include <functional>
#include <inttypes.h>
#include <iostream>
#include <iomanip>
#include <filesystem>

//----------------------------------------
//
//----------------------------------------
inline std::string base64_encode(const std::string& input) {
  static constexpr char base64_chars[]{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" };

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
inline std::string base64_decode(const std::string& encoded) {
    static constexpr unsigned char decode_table[256] {
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
        64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
        64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
    };

    std::string result;
    result.reserve((encoded.size() / 4) * 3);

    for (size_t i = 0; i < encoded.size(); i += 4) {
        unsigned char a = decode_table[static_cast<unsigned char>(encoded[i])];
        unsigned char b = decode_table[static_cast<unsigned char>(encoded[i + 1])];
        unsigned char c = decode_table[static_cast<unsigned char>(encoded[i + 2])];
        unsigned char d = decode_table[static_cast<unsigned char>(encoded[i + 3])];

        result += (a << 2) | (b >> 4);
        if (encoded[i + 2] != '=') result += (b << 4) | (c >> 2);
        if (encoded[i + 3] != '=') result += (c << 6) | d;
    }

    return result;
}

//----------------------------------------
//
//----------------------------------------
inline std::string url_encode(const std::string& value) {
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
inline std::string url_decode(const std::string& str) {
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