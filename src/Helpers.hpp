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
