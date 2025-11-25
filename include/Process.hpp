#pragma once

#include "Stream.hpp"

#include <string>
#include <vector>
#include <optional>
#include <unistd.h>

namespace cpppwn {

using handle_t = int;
using address_t = size_t;
using buffer_t = std::vector<std::byte>;

class Process;

class Process : public Stream {
public:
    explicit Process(const std::string& process_name);
    explicit Process(const std::string& executable, const std::vector<std::string>& args);

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

    std::optional<address_t> findSignature(const std::string& signature);

    void writeMemory(const address_t address, const buffer_t& buffer);

    buffer_t readMemory(const address_t address, size_t size);

    void loadLibrary(const std::string& path); //call dlopen()

    ~Process() override;

private:
    std::string process_name_;
    handle_t process_handle_;
    handle_t child_stdin_;
    handle_t child_stdout_;
    pid_t pid_;
    
    address_t getBaseAddress(const std::string& module_name = "");
};

}
