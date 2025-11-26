#pragma once

#include <Remote.hpp>

#include <memory>
#include <string>
#include <optional>
#include <cstdint>

namespace cpppwn {

//----------------------------------------
//
//----------------------------------------
struct TlsConfig {
  std::string cert_file;
  std::string key_file;
  std::optional<std::string> ca_file;
  bool verify_client = false;
  std::optional<std::string> cipher_list;
    
  TlsConfig(std::string cert, std::string key) : cert_file(std::move(cert)), key_file(std::move(key)) {
  }
};

//----------------------------------------
//
//----------------------------------------
class Server {
public:
  class ServerImpl; 

  explicit Server(uint16_t port, const std::string& bind_addr = "0.0.0.0");
    
  explicit Server(uint16_t port, const TlsConfig& tls_config, const std::string& bind_addr = "0.0.0.0");
    
  [[nodiscard]] std::unique_ptr<Remote> accept();
    
  void close();
    
  [[nodiscard]] bool is_open() const noexcept;
    
  ~Server();
    
  // Prevent copying
  Server(const Server&) = delete;
  Server& operator=(const Server&) = delete;
  static std::pair<std::string, std::string> 
  generate_self_signed_cert(const std::string& output_dir = "./", const std::string& common_name = "localhost", int days_valid = 365);

private:
    
    asio::io_context io_;
    std::unique_ptr<ServerImpl> impl_;
};

} // namespace cpppwn
