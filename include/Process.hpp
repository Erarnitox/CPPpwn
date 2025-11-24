#pragma once
#include "Stream.hpp"

#include <string>
#include <unistd.h>

namespace cppwntools {

class Process : public Stream {
public:
    explicit Process(const std::string& command);

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

    ~Process() override;

private:
    int child_stdin_;
    int child_stdout_;
    pid_t pid_;
};
}
