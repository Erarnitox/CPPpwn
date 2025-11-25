#pragma once
#include <string>
#include <cstddef>

namespace cpppwn {

class Stream {
public:
    virtual ~Stream() = default;

    virtual void send(const std::string& data) noexcept = 0;
    virtual void sendline(const std::string& data) noexcept = 0;

    [[nodiscard]] virtual std::string recv(std::size_t size) noexcept = 0;
    [[nodiscard]] virtual std::string recvuntil(const std::string& delim) noexcept = 0;
    [[nodiscard]] virtual std::string recvline() noexcept = 0;
    [[nodiscard]] virtual std::string recvall() = 0;

    [[nodiscard]] virtual int getInputStream() noexcept = 0;
    [[nodiscard]] virtual int getOutputStream() noexcept = 0;

    [[nodiscard]] virtual bool is_alive() const noexcept = 0;
    virtual void close() noexcept = 0;

    virtual void interactive() = 0;
};
}
