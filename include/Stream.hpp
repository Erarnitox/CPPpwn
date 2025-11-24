#pragma once
#include <string>
#include <cstddef>

namespace cppwntools {

class Stream {
public:
    virtual ~Stream() = default;

    virtual void send(const std::string& data) = 0;
    virtual void sendline(const std::string& data) = 0;

    virtual std::string recv(std::size_t size) = 0;
    virtual std::string recvuntil(const std::string& delim) = 0;
    virtual std::string recvline() = 0;
    virtual std::string recvall() = 0;

    virtual int getInputStream() = 0;
    virtual int getOutputStream() = 0;

    virtual bool is_alive() const = 0;
    virtual void close() = 0;

    virtual void interactive() = 0;
};
}
