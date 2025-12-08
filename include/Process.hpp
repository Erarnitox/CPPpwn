#pragma once

#include "Stream.hpp"

#include <string>
#include <vector>
#include <optional>
#include <unistd.h>

namespace cpppwn {

using byte_t = char;
using handle_t = int;
using address_t = size_t;
using buffer_t = std::vector<byte_t>;

class Process : public Stream {
public:
    template <typename T>
    T readValue(const address_t address) const {
        auto points_value_buffer = this->readMemory(address, sizeof(T));
        return *reinterpret_cast<T*>(&(*points_value_buffer.begin()));
    }
   
    template <typename T>
    void writeValue(const address_t address, const T& value) {
        const auto value_size{ sizeof(value) };
        const auto value_base_address = reinterpret_cast<const byte_t*>(&value);

        buffer_t hacked_value_buffer;
        hacked_value_buffer.reserve(value_size);

        for(size_t i{ 0 }; i < value_size; ++i) {
            hacked_value_buffer.push_back(value_base_address[i]);
        }
        this->writeMemory(address, hacked_value_buffer);
    }


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

    std::optional<address_t> findSignature(const std::string& signature) const;

    void writeMemory(const address_t address, const buffer_t& buffer);

    buffer_t readMemory(const address_t address, size_t size) const;

    void loadLibrary(const std::string& path); //call dlopen()

    address_t getBaseAddress(const std::string& module_name = "") const;

    ~Process() override;

private:
    std::string process_name_;
    handle_t process_handle_;
    handle_t child_stdin_;
    handle_t child_stdout_;
    pid_t pid_;
};

}
