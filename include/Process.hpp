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

Process attach(const std::string& process_name);  

class Process : public Stream {
public:
    explicit Process(const std::string& command);

    void send(const std::string& data) noexcept override;
    void sendline(const std::string& data) noexcept override;

    [[nodiscard]] std::string recv(std::size_t size) noexcept override;
    [[nodiscard]] std::string recvuntil(const std::string& delim) noexcept override;
    [[nodiscard]] std::string recvline() noexcept override;
    [[nodiscard]] std::string recvall() noexcept override;

    [[nodiscard]] bool is_alive() const noexcept override;
    void close() noexcept override;

    [[nodiscard]] int getInputStream() noexcept override;
    [[nodiscard]] int getOutputStream() noexcept override;

    void interactive() override;

    std::optional<address_t> findSignature(const std::string& signature);

    void writeMemory(const address_t address, const buffer_t& buffer);
    buffer_t readMemory(const address_t address);

    ~Process() override;
    friend Process attach(const std::string& process_name);  

private:
    std::string process_name_;
    handle_t process_handle_;
    handle_t child_stdin_;
    handle_t child_stdout_;
    pid_t pid_;
    
    address_t getBaseAddress(const std::string module_name = "");
};

}
