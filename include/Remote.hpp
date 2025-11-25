#pragma once
#include "Stream.hpp"

#include <asio.hpp>
#include <string>

namespace cpppwn {

class Remote : public Stream {
public:
    Remote(const std::string& host, uint16_t port);

    void send(const std::string& data) noexcept override;
    void sendline(const std::string& data) noexcept override;

    [[nodiscard]] std::string recv(std::size_t size) noexcept override;
    [[nodiscard]] std::string recvuntil(const std::string& delim) noexcept override;
    [[nodiscard]] std::string recvline() noexcept override;
    [[nodiscard]] std::string recvall() override;

    [[nodiscard]] bool is_alive() const noexcept override;
    void close() noexcept override;

    [[nodiscard]] int getInputStream() noexcept override;
    [[nodiscard]] int getOutputStream() noexcept override;

    void interactive() override;

    void swap_socket(asio::ip::tcp::socket&& socket);

    ~Remote();

private:
    asio::io_context io_;
    asio::ip::tcp::socket socket_;
};
} 
