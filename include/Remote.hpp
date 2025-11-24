#pragma once
#include "Stream.hpp"

#include <asio.hpp>
#include <string>

namespace cppwntools {

class Remote : public Stream {
public:
    Remote(const std::string& host, uint16_t port);

    void send(const std::string& data) override;
    void sendline(const std::string& data) override;

    std::string recv(std::size_t size) override;
    std::string recvuntil(const std::string& delim) override;
    std::string recvline() override;
    std::string recvall() override;

    bool is_alive() const override;
    void close() override;

    int getInputStream() override;
    int getOutputStream() override;

    void interactive() override;

    void swap_socket(asio::ip::tcp::socket&& socket);

    ~Remote();

private:
    asio::io_context io_;
    asio::ip::tcp::socket socket_;
};
} 
