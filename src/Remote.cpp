#include "../include/Remote.hpp"
#include "Helpers.hpp"

#include <asio/read_until.hpp>
#include <asio/write.hpp>
#include <iostream>

namespace cppwntools {

//----------------------------------------
//
//----------------------------------------
Remote::Remote(const std::string& host, uint16_t port)
    : socket_(io_) {
    asio::ip::tcp::resolver resolver(io_);
    auto endpoints = resolver.resolve(host, std::to_string(port));
    asio::connect(socket_, endpoints);
}

//----------------------------------------
//
//----------------------------------------
void Remote::send(const std::string& data) {
    asio::write(socket_, asio::buffer(data));
}

//----------------------------------------
//
//----------------------------------------
void Remote::sendline(const std::string& data) {
    send(data + "\n");
}

//----------------------------------------
//
//----------------------------------------
std::string Remote::recv(std::size_t size) {
    std::vector<char> buf(size);
    size_t len = asio::read(socket_, asio::buffer(buf, size));
    return std::string(buf.begin(), buf.begin() + len);
}

//----------------------------------------
//
//----------------------------------------
std::string Remote::recvuntil(const std::string& delim) {
    asio::streambuf buf;
    asio::read_until(socket_, buf, delim);
    return std::string(asio::buffers_begin(buf.data()), asio::buffers_end(buf.data()));
}

//----------------------------------------
//
//----------------------------------------
bool Remote::is_alive() const {
    return socket_.is_open();
}

//----------------------------------------
//
//----------------------------------------
void Remote::close() {
    asio::error_code ec;
    socket_.close(ec);
}

//----------------------------------------
//
//----------------------------------------
void Remote::interactive() {
    std::atomic<bool> running{true};
    std::thread input_thread(copy_stdin_to_stream, this, std::ref(running));
    std::thread output_thread(copy_stream_to_stdout, this, std::ref(running));

    input_thread.join();
    output_thread.join();
}

//----------------------------------------
//
//----------------------------------------
Remote::~Remote() {
  if(is_alive()) {
    close();
  }
}

//----------------------------------------
//
//----------------------------------------
int Remote::getInputStream() {
  return socket_.native_handle();
}

//----------------------------------------
//
//----------------------------------------
int Remote::getOutputStream() {
  return socket_.native_handle(); 
}

//----------------------------------------
//
//----------------------------------------
std::string Remote::recvline() {
    return recvuntil("\n");
}

//----------------------------------------
//
//----------------------------------------
std::string Remote::recvall() {
    std::string result;
    std::array<char, 4096> buf;
    asio::error_code ec;
    while (true) {
        size_t len = socket_.read_some(asio::buffer(buf), ec);
        if (ec == asio::error::eof || ec == asio::error::connection_reset)
            break;
        if (ec)
            throw std::runtime_error("recvall failed: " + ec.message());
        result.append(buf.data(), len);
    }
    return result;
}

//----------------------------------------
//
//----------------------------------------
void Remote::swap_socket(asio::ip::tcp::socket&& socket) {
    socket_ = std::move(socket);
}

}
