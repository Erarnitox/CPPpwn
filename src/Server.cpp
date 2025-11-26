#include <Server.hpp>
#include <Remote.hpp>

#include <asio/ip/tcp.hpp>
#include <asio/ssl.hpp>
#include <memory>
#include <optional>
#include <filesystem>
#include <stdexcept>
#include <fstream>

namespace fs = std::filesystem;

namespace cpppwn {

//----------------------------------------
// Server Implementation (Pimpl pattern)
//----------------------------------------
class Server::ServerImpl {
public:
  virtual ~ServerImpl() = default;
  virtual std::unique_ptr<Remote> accept() = 0;
  virtual void close() = 0;
  virtual bool is_open() const = 0;
};

//----------------------------------------
//
//----------------------------------------
class TcpServerImpl : public Server::ServerImpl {
public:
  //----------------------------------------
  //
  //----------------------------------------
  explicit TcpServerImpl(asio::io_context& io, uint16_t port, const std::string& bind_addr) 
  : acceptor_(io) {
    asio::ip::tcp::endpoint endpoint;
        
    if(bind_addr.empty() || bind_addr == "0.0.0.0") {
      endpoint = asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port);
    } else if(bind_addr == "::") {
      endpoint = asio::ip::tcp::endpoint(asio::ip::tcp::v6(), port);
    } else {
      asio::ip::tcp::resolver resolver(io);
      auto results = resolver.resolve(bind_addr, std::to_string(port));
      endpoint = *results.begin();
    }
        
    acceptor_.open(endpoint.protocol());
    acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
    acceptor_.bind(endpoint);
    acceptor_.listen();
  }
    
    //----------------------------------------
    //
    //----------------------------------------
    std::unique_ptr<Remote> accept() override {
      asio::ip::tcp::socket socket(acceptor_.get_executor());
      acceptor_.accept(socket);
      return std::make_unique<Remote>(std::move(socket));
    }
    
    //----------------------------------------
    //
    //----------------------------------------
    void close() override {
      asio::error_code ec;
      acceptor_.close(ec);
    }
    
    //----------------------------------------
    //
    //----------------------------------------
    bool is_open() const override {
      return acceptor_.is_open();
    }
    
private:
    asio::ip::tcp::acceptor acceptor_;
};

//----------------------------------------
//
//----------------------------------------
class TlsServerImpl : public Server::ServerImpl {
public:
  explicit TlsServerImpl(asio::io_context& io, uint16_t port, 
    //----------------------------------------
    //
    //----------------------------------------
    const std::string& bind_addr, const TlsConfig& tls_config)
        : acceptor_(io), ssl_ctx_(asio::ssl::context::tlsv12_server) {
        
          // Load certificate and private key
          if(not fs::exists(tls_config.cert_file)) {
            throw std::runtime_error("Certificate file not found: " + tls_config.cert_file);
          }
        
          if(not fs::exists(tls_config.key_file)) {
            throw std::runtime_error("Private key file not found: " + tls_config.key_file);
          }
        
          ssl_ctx_.use_certificate_chain_file(tls_config.cert_file);
          ssl_ctx_.use_private_key_file(tls_config.key_file, asio::ssl::context::pem);
        
          // Load CA chain if provided
          if(tls_config.ca_file && fs::exists(*tls_config.ca_file)) {
            ssl_ctx_.load_verify_file(*tls_config.ca_file);
          }
        
          // Set verification mode for client certificates
          if(tls_config.verify_client) {
            ssl_ctx_.set_verify_mode(asio::ssl::verify_peer | asio::ssl::verify_fail_if_no_peer_cert);
          } else {
            ssl_ctx_.set_verify_mode(asio::ssl::verify_none);
          }
        
          // Configure ciphers if specified
          if(tls_config.cipher_list) {
            SSL_CTX_set_cipher_list(ssl_ctx_.native_handle(), tls_config.cipher_list->c_str());
          }
        
          // Set up acceptor
          asio::ip::tcp::endpoint endpoint;
        
          if(bind_addr.empty() || bind_addr == "0.0.0.0") {
            endpoint = asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port);
          } else if(bind_addr == "::") {
            endpoint = asio::ip::tcp::endpoint(asio::ip::tcp::v6(), port);
          } else {
            asio::ip::tcp::resolver resolver(io);
            auto results = resolver.resolve(bind_addr, std::to_string(port));
            endpoint = *results.begin();
          }
        
          acceptor_.open(endpoint.protocol());
          acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
          acceptor_.bind(endpoint);
          acceptor_.listen();
    }
    
    //----------------------------------------
    //
    //----------------------------------------
    std::unique_ptr<Remote> accept() override {
      asio::ssl::stream<asio::ip::tcp::socket> ssl_socket(acceptor_.get_executor(), ssl_ctx_);
      acceptor_.accept(ssl_socket.lowest_layer());
      ssl_socket.handshake(asio::ssl::stream_base::server);
      return std::make_unique<Remote>(std::move(ssl_socket));
    }
    
    //----------------------------------------
    //
    //----------------------------------------
    void close() override {
      asio::error_code ec;
      acceptor_.close(ec);
    }
    
    //----------------------------------------
    //
    //----------------------------------------
    bool is_open() const override {
        return acceptor_.is_open();
    }
    
private:
  asio::ip::tcp::acceptor acceptor_;
  asio::ssl::context ssl_ctx_;
};

//----------------------------------------
// Plain TCP server constructor
//----------------------------------------
Server::Server(uint16_t port, const std::string& bind_addr): io_(), impl_(nullptr) {
  impl_ = std::make_unique<TcpServerImpl>(io_, port, bind_addr);
}

//----------------------------------------
// TLS/SSL server constructor
//----------------------------------------
Server::Server(uint16_t port, const TlsConfig& tls_config, const std::string& bind_addr)
  : io_(), impl_(nullptr) {
    impl_ = std::make_unique<TlsServerImpl>(io_, port, bind_addr, tls_config);
}

//----------------------------------------
// Accept incoming connection
//----------------------------------------
std::unique_ptr<Remote> Server::accept() {
  if(not impl_) {
    throw std::runtime_error("Server not initialized");
  }
  return impl_->accept();
}

//----------------------------------------
// Close the server
//----------------------------------------
void Server::close() {
  if(impl_) {
    impl_->close();
  }
}

//----------------------------------------
// Check if server is open
//----------------------------------------
bool Server::is_open() const noexcept {
  return impl_ && impl_->is_open();
}

//----------------------------------------
// Destructor
//----------------------------------------
Server::~Server() {
  if(is_open()) {
    close();
  }
}

//----------------------------------------
// Helper: Generate self-signed certificate (for testing)
//----------------------------------------
std::pair<std::string, std::string> 
Server::generate_self_signed_cert(const std::string& output_dir, 
  const std::string& common_name, int days_valid) {
  const fs::path dir{output_dir};
    
  // Create directory if it doesn't exist
  if(not fs::exists(dir)) {
    fs::create_directories(dir);
  }
    
  const auto cert_path = dir / "server.crt";
  const auto key_path = dir / "server.key";
    
  // Generate certificate using OpenSSL command-line
  // Note: This is a simple implementation. For production, use OpenSSL API directly
  const std::string cmd = 
    "openssl req -x509 -newkey rsa:4096 -nodes "
    "-keyout " + key_path.string() + " "
    "-out " + cert_path.string() + " "
    "-days " + std::to_string(days_valid) + " "
    "-subj \"/CN=" + common_name + "\" "
    "2>/dev/null";
    
  const int result = std::system(cmd.c_str());
    
  if(result != 0) {
    throw std::runtime_error("Failed to generate self-signed certificate. Make sure OpenSSL is installed.");
  }
    
  if(not fs::exists(cert_path) || not fs::exists(key_path)) {
    throw std::runtime_error("Certificate or key file was not created");
  }
    
  return {cert_path.string(), key_path.string()};
}

}
