#pragma once

#include <atomic>
#include <Stream.hpp>
#include <iostream>

//----------------------------------------
//
//----------------------------------------
static inline void copy_stdin_to_stream(cppwntools::Stream* stream, std::atomic<bool>& running) {
    std::string line;
    while (running && std::getline(std::cin, line)) {
        stream->sendline(line);
    }
    running = false;
}

//----------------------------------------
//
//----------------------------------------
static inline void copy_stream_to_stdout(cppwntools::Stream* stream, std::atomic<bool>& running) {
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
