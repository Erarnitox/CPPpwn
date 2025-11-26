#pragma once

#include "Stream.hpp"
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <string>

namespace cpppwn {

class Remote : public Stream {
public:
    class SocketImpl;

    explicit Remote(const std::string& host, uint16_t port);

    explicit Remote(const std::string& host, uint16_t port, 
        bool use_tls, bool verify_certificate = false
    );

    explicit Remote(const std::string& host, uint16_t port, 
        const std::string& proxy, bool use_tls = false);

    explicit Remote(const std::string& host, uint16_t port,
                   std::shared_ptr<asio::ssl::context> ssl_ctx);

    explicit Remote(asio::ip::tcp::socket socket);
    explicit Remote(asio::ssl::stream<asio::ip::tcp::socket> ssl_socket);

    void send(const std::string& data) override;
    void sendline(const std::string& data) override;

    [[nodiscard]] std::string recv(std::size_t size) override;
    [[nodiscard]] std::string recvuntil(const std::string& delim) override;
    [[nodiscard]] std::string recvline() override;
    [[nodiscard]] std::string recvall() override;

    [[nodiscard]] bool is_alive() const noexcept override;
    void close() override;

    [[nodiscard]] int getInputStream() noexcept override;
    [[nodiscard]] int getOutputStream() noexcept override;

    void interactive() override;

    void swap_socket(asio::ip::tcp::socket&& socket);

    ~Remote() override;

    Remote(const Remote&) = delete;
    Remote& operator=(const Remote&) = delete;

private:
    asio::io_context io_;
    std::unique_ptr<SocketImpl> socket_;
};
} 
