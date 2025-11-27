#include <Remote.hpp>
#include "Helpers.hpp"

#include <asio/read_until.hpp>
#include <asio/write.hpp>
#include <asio/ssl.hpp>
#include <cstdint>
#include <regex>

namespace cpppwn {
  namespace {

    //----------------------------------------
    //
    //----------------------------------------
    struct ProxyConfig {
      enum class Type { HTTP, SOCKS };
      Type type;
      std::string host;
      uint16_t port;
      std::optional<std::string> username;
      std::optional<std::string> password;
    };

    //----------------------------------------
    //
    //----------------------------------------
    std::optional<ProxyConfig> parseProxyUrl(std::string_view proxy_url) {
      // Regex pattern: (http|socks5)://(user:pass@)?host:port
      std::regex pattern(R"(^(http|socks5)://(?:([^:@]+):([^@]+)@)?([^:]+):(\d+)$)");
      std::smatch matches;
      std::string url_str(proxy_url);
        
      if(not std::regex_match(url_str, matches, pattern)) {
        return std::nullopt;
      }
        
      ProxyConfig config;
      config.type = (matches[1] == "http") ? ProxyConfig::Type::HTTP : ProxyConfig::Type::SOCKS;
      config.host = matches[4];
      config.port = static_cast<uint16_t>(std::stoi(matches[5]));
        
      if(matches[2].matched) {
        config.username = matches[2];
        config.password = matches[3];
      }
        
      return config;
    }

    //----------------------------------------
    //
    //----------------------------------------
    void socks5Connect(asio::ip::tcp::socket& socket, 
                      const std::string& target_host,
                      uint16_t target_port,
                      const std::optional<std::string>& username = std::nullopt,
                      const std::optional<std::string>& password = std::nullopt) {
        
      // SOCKS5 greeting
      std::vector<uint8_t> greeting = {0x05, 0x01}; // Version 5, 1 auth method
        
      if(username && password) {
        greeting.push_back(0x02); // Username/password auth
      } else {
        greeting.push_back(0x00); // No authentication
      }
        
      asio::write(socket, asio::buffer(greeting));
        
      // Read server choice
      std::array<uint8_t, 2> response;
      asio::read(socket, asio::buffer(response));
        
      if(response[0] != 0x05) {
        throw std::runtime_error("Invalid SOCKS5 version in response");
      }
        
      // Handle authentication if required
      if(response[1] == 0x02) {
        if(not username.has_value() || not password.has_value()) {
          throw std::runtime_error("SOCKS5 server requires authentication");
        }
            
        // Send username/password
        std::vector<uint8_t> auth;
        auth.push_back(0x01); // Auth version
        auth.push_back(static_cast<uint8_t>(username->length()));
        auth.insert(auth.end(), username->begin(), username->end());
        auth.push_back(static_cast<uint8_t>(password->length()));
        auth.insert(auth.end(), password->begin(), password->end());
            
        asio::write(socket, asio::buffer(auth));
            
        std::array<uint8_t, 2> auth_response;
        asio::read(socket, asio::buffer(auth_response));
            
        if(auth_response[1] != 0x00) {
          throw std::runtime_error("SOCKS5 authentication failed");
        }
      } else if(response[1] != 0x00) {
        throw std::runtime_error("SOCKS5 authentication method not supported");
      }
        
      // Send connection request
      std::vector<uint8_t> connect_req = {
        0x05, // Version
        0x01, // CONNECT command
        0x00, // Reserved
        0x03  // Domain name address type
      };
        
      connect_req.push_back(static_cast<uint8_t>(target_host.length()));
      connect_req.insert(connect_req.end(), target_host.begin(), target_host.end());
      connect_req.push_back(static_cast<uint8_t>(target_port >> 8));
      connect_req.push_back(static_cast<uint8_t>(target_port & 0xFF));
        
      asio::write(socket, asio::buffer(connect_req));
        
      // Read connection response
      std::array<uint8_t, 10> connect_response;
      asio::read(socket, asio::buffer(connect_response, 4));
        
      if(connect_response[0] != 0x05) {
        throw std::runtime_error("Invalid SOCKS5 version in connect response");
      }
        
      if(connect_response[1] != 0x00) {
        throw std::runtime_error("SOCKS5 connection failed: " + std::to_string(connect_response[1]));
      }
        
      // Read remaining response based on address type
      uint8_t atyp = connect_response[3];
      size_t remaining = 0;
        
      if(atyp == 0x01) { // IPv4
        remaining = 6; // 4 bytes IP + 2 bytes port
      } else if(atyp == 0x03) { // Domain
        uint8_t len;
        asio::read(socket, asio::buffer(&len, 1));
        remaining = len + 2; // domain + port
      } else if (atyp == 0x04) { // IPv6
        remaining = 18; // 16 bytes IP + 2 bytes port
      }
        
      std::vector<uint8_t> remaining_data(remaining);
      asio::read(socket, asio::buffer(remaining_data));
    }
    
    //----------------------------------------
    //
    //----------------------------------------
    void httpProxyConnect(asio::ip::tcp::socket& socket,
                         const std::string& target_host,
                         uint16_t target_port,
                         const std::optional<std::string>& username = std::nullopt,
                         const std::optional<std::string>& password = std::nullopt) {
        
      std::ostringstream request;
      request << "CONNECT " << target_host << ":" << target_port << " HTTP/1.1\r\n";
      request << "Host: " << target_host << ":" << target_port << "\r\n";
        
      // Add proxy authentication if credentials provided
      if(username.has_value() && password.has_value()) {
        std::string credentials = username.value() + ":" + password.value();
        request << "Proxy-Authorization: Basic " << base64_encode(credentials) << "\r\n";
      }
      request << "\r\n";

      asio::write(socket, asio::buffer(request.str()));
        
      // Read response
      asio::streambuf response;
      asio::read_until(socket, response, "\r\n\r\n");
        
      std::istream response_stream(&response);
      std::string http_version;
      unsigned int status_code;
      std::string status_message;
        
      response_stream >> http_version >> status_code;
      std::getline(response_stream, status_message);
        
      if(status_code != 200) {
        throw std::runtime_error("HTTP proxy connection failed: " 
            + std::to_string(status_code) + " " + status_message);
      }
    }
  } // anon namespace

//----------------------------------------
//
//----------------------------------------
class Remote::SocketImpl {
  public:
    virtual void write(const std::string& data) = 0;
    virtual size_t read(char* buffer, size_t size) = 0;
    virtual size_t read_some(char* buffer, size_t size, asio::error_code& ec) = 0;
    virtual void read_until(asio::streambuf& buf, const std::string& delim) = 0;
    virtual bool is_open() const = 0;
    virtual bool is_tls() const = 0;
    virtual void close() = 0;
    virtual int native_handle() = 0;
    virtual ~SocketImpl() = default;
};

//----------------------------------------
//
//----------------------------------------
class TcpSocketImpl : public Remote::SocketImpl {
  public:
    //----------------------------------------
    //
    //----------------------------------------
    explicit TcpSocketImpl(asio::ip::tcp::socket socket) : socket_(std::move(socket)) {
    }
    
    //----------------------------------------
    //
    //----------------------------------------
    void write(const std::string& data) override {
      asio::write(socket_, asio::buffer(data));
    }
    
    //----------------------------------------
    //
    //----------------------------------------
    size_t read(char* buffer, size_t size) override {
      return asio::read(socket_, asio::buffer(buffer, size));
    }
    
    //----------------------------------------
    //
    //----------------------------------------
    size_t read_some(char* buffer, size_t size, asio::error_code& ec) override {
      return socket_.read_some(asio::buffer(buffer, size), ec);
    }
    
    //----------------------------------------
    //
    //----------------------------------------
    void read_until(asio::streambuf& buf, const std::string& delim) override {
      asio::read_until(socket_, buf, delim);
    }
    
    //----------------------------------------
    //
    //----------------------------------------
    bool is_open() const override {
      return socket_.is_open();
    }
    
    //----------------------------------------
    //
    //----------------------------------------
    bool is_tls() const override {
      return false;
    }

    //----------------------------------------
    //
    //----------------------------------------
    void close() override {
      asio::error_code ec;
      socket_.close(ec);
    }
    
    //----------------------------------------
    //
    //----------------------------------------
    int native_handle() override {
      return socket_.native_handle();
    }
    
  private:
    asio::ip::tcp::socket socket_;
};


//----------------------------------------
//
//----------------------------------------
class TlsSocketImpl : public Remote::SocketImpl {
  public:
    //----------------------------------------
    //
    //----------------------------------------
    explicit TlsSocketImpl(asio::ssl::stream<asio::ip::tcp::socket> socket)
      : socket_(std::move(socket)) {}
    
    //----------------------------------------
    //
    //----------------------------------------
    void write(const std::string& data) override {
      asio::write(socket_, asio::buffer(data));
    }
    
    //----------------------------------------
    //
    //----------------------------------------
    size_t read(char* buffer, size_t size) override {
      return asio::read(socket_, asio::buffer(buffer, size));
    }
    
    //----------------------------------------
    //
    //----------------------------------------
    size_t read_some(char* buffer, size_t size, asio::error_code& ec) override {
      return socket_.read_some(asio::buffer(buffer, size), ec);
    }
    
    //----------------------------------------
    //
    //----------------------------------------
    void read_until(asio::streambuf& buf, const std::string& delim) override {
      asio::read_until(socket_, buf, delim);
    }

    //----------------------------------------
    //
    //----------------------------------------
    bool is_open() const override {
      return socket_.lowest_layer().is_open();
    }

    //----------------------------------------
    //
    //----------------------------------------
    bool is_tls() const override {
      return true;
    }
   
    //----------------------------------------
    //
    //----------------------------------------
    void close() override {
      asio::error_code ec;
      socket_.lowest_layer().close(ec);
    }
    
    //----------------------------------------
    //
    //----------------------------------------
    int native_handle() override {
      return socket_.lowest_layer().native_handle();
    }
    
  private:
    asio::ssl::stream<asio::ip::tcp::socket> socket_;
};

//----------------------------------------
//
//----------------------------------------
Remote::Remote(const std::string& host, uint16_t port)
  : io_(), socket_(nullptr) {

  asio::ip::tcp::socket socket(io_);
  asio::ip::tcp::resolver resolver(io_);
  auto endpoints = resolver.resolve(host, std::to_string(port));
  asio::connect(socket, endpoints);

  socket_ = std::make_unique<TcpSocketImpl>(std::move(socket));
}

//----------------------------------------
//
//----------------------------------------
Remote::Remote(const std::string& host, uint16_t port, bool use_tls, bool verify_certificate)
  : io_(), socket_(nullptr) {
    
  if(not use_tls) {
    asio::ip::tcp::socket socket(io_);
    asio::ip::tcp::resolver resolver(io_);
    auto endpoints = resolver.resolve(host, std::to_string(port));
    asio::connect(socket, endpoints);
    socket_ = std::make_unique<TcpSocketImpl>(std::move(socket));
    return;
  }
    
  asio::ssl::context ssl_ctx(asio::ssl::context::tlsv12_client);
    
  if(verify_certificate) {
    ssl_ctx.set_default_verify_paths();
    ssl_ctx.set_verify_mode(asio::ssl::verify_peer);
  } else {
    ssl_ctx.set_verify_mode(asio::ssl::verify_none);
  }
    
  asio::ssl::stream<asio::ip::tcp::socket> ssl_socket(io_, ssl_ctx);
    
  if(not SSL_set_tlsext_host_name(ssl_socket.native_handle(), host.c_str())) {
    throw std::runtime_error("Failed to set SNI hostname");
  }
    
  // Connect to server
  asio::ip::tcp::resolver resolver(io_);
  auto endpoints = resolver.resolve(host, std::to_string(port));
  asio::connect(ssl_socket.lowest_layer(), endpoints);
    
  ssl_socket.handshake(asio::ssl::stream_base::client);
  socket_ = std::make_unique<TlsSocketImpl>(std::move(ssl_socket));
}

//----------------------------------------
//
//----------------------------------------
Remote::Remote(const std::string& host, uint16_t port, 
               const std::string& proxy_url, bool use_tls): io_(), socket_(nullptr) {

    auto proxy_config = parseProxyUrl(proxy_url);

    if(not proxy_config) {
      throw std::runtime_error("Invalid proxy URL format. Expected: (http|socks5)://[user:pass@]host:port");
    }
    
    // Connect to proxy server
    asio::ip::tcp::socket socket(io_);
    asio::ip::tcp::resolver resolver(io_);
    auto proxy_endpoints = resolver.resolve(proxy_config->host, std::to_string(proxy_config->port));
    asio::connect(socket, proxy_endpoints);
    
    // Perform proxy handshake
    if(proxy_config->type == ProxyConfig::Type::SOCKS) {
      socks5Connect(socket, host, port, proxy_config->username, proxy_config->password);
    } else {
      httpProxyConnect(socket, host, port, proxy_config->username, proxy_config->password);
    }
    
    // If TLS is requested, wrap the socket in SSL
    if(use_tls) {
      asio::ssl::context ssl_ctx(asio::ssl::context::tlsv12_client);
      ssl_ctx.set_default_verify_paths();
      ssl_ctx.set_verify_mode(asio::ssl::verify_peer);
        
      asio::ssl::stream<asio::ip::tcp::socket> ssl_socket(std::move(socket), ssl_ctx);
        
      if(not SSL_set_tlsext_host_name(ssl_socket.native_handle(), host.c_str())) {
        throw std::runtime_error("Failed to set SNI hostname");
      }
        
      ssl_socket.handshake(asio::ssl::stream_base::client);
      socket_ = std::make_unique<TlsSocketImpl>(std::move(ssl_socket));
    } else {
      socket_ = std::make_unique<TcpSocketImpl>(std::move(socket));
    }
}

//----------------------------------------
//
//----------------------------------------
Remote::Remote(const std::string& host, uint16_t port, 
  std::shared_ptr<asio::ssl::context> ssl_ctx): io_(), socket_(nullptr) {
  
  if (not ssl_ctx) {
    throw std::invalid_argument("SSL context cannot be null");
  }
    
  // Create SSL stream with custom context
  asio::ssl::stream<asio::ip::tcp::socket> ssl_socket(io_, *ssl_ctx);
    
  // Set SNI hostname
  if(not SSL_set_tlsext_host_name(ssl_socket.native_handle(), host.c_str())) {
    throw std::runtime_error("Failed to set SNI hostname");
  }
    
  // Connect to server
  asio::ip::tcp::resolver resolver(io_);
  auto endpoints = resolver.resolve(host, std::to_string(port));
  asio::connect(ssl_socket.lowest_layer(), endpoints);
    
  // Perform TLS handshake
  ssl_socket.handshake(asio::ssl::stream_base::client);
    
  socket_ = std::make_unique<TlsSocketImpl>(std::move(ssl_socket));
}

//----------------------------------------
//
//----------------------------------------
void Remote::send(const std::string& data) {
  if(not socket_) {
    throw std::runtime_error("No socket available!");
  }
  socket_->write(data);
}

//----------------------------------------
//
//----------------------------------------
void Remote::sendline(const std::string& data) {
  send(data + "\n");
}

//----------------------------------------
//
//----------------------------------------
std::string Remote::recv(std::size_t size) {
  if(not socket_) {
    throw std::runtime_error("No socket available!");
  }

  std::vector<char> buf(size);
  size_t len = socket_->read(buf.data(), size);
  return std::string(buf.begin(), buf.begin() + len);
}

//----------------------------------------
//
//----------------------------------------
std::string Remote::recvuntil(const std::string& delim) {
  if(not socket_) {
    throw std::runtime_error("No socket available!");
  }

  asio::streambuf buf;
  socket_->read_until(buf, delim);
  return std::string(asio::buffers_begin(buf.data()), asio::buffers_end(buf.data()));
}

//----------------------------------------
//
//----------------------------------------
bool Remote::is_alive() const noexcept {
    return socket_ && socket_->is_open();
}

//----------------------------------------
//
//----------------------------------------
void Remote::close() {
  if(socket_)
    socket_->close();
}

//----------------------------------------
//
//----------------------------------------
void Remote::interactive() {
    std::atomic<bool> running{true};
    
    //TODO: Doesn't work for TLS
    std::thread input_thread(copy_stdin_to_stream, this, std::ref(running));
    std::thread output_thread(copy_stream_to_stdout, this, std::ref(running));

    input_thread.join();
    output_thread.join();
}

//----------------------------------------
//
//----------------------------------------
Remote::~Remote() {
  if(is_alive()) {
    close();
  }
}

//----------------------------------------
//
//----------------------------------------
int Remote::getInputStream() noexcept {
  return socket_ ? socket_->native_handle() : -1;
}

//----------------------------------------
//
//----------------------------------------
int Remote::getOutputStream() noexcept {
  return socket_ ? socket_->native_handle() : -1; 
}

//----------------------------------------
//
//----------------------------------------
std::string Remote::recvline() {
  return recvuntil("\n");
}

//----------------------------------------
//
//----------------------------------------
std::string Remote::recvall() {
  std::string result;
  std::array<char, 4096> buf;
  asio::error_code ec;

  while(true) {
    size_t len = socket_->read_some(buf.data(), buf.size(), ec);

    if(ec == asio::error::eof || ec == asio::error::connection_reset) break;
    if(ec) throw std::runtime_error("recvall failed: " + ec.message());
        
    result.append(buf.data(), len);
  }
  return result;
}

//----------------------------------------
//
//----------------------------------------
void Remote::swap_socket(asio::ip::tcp::socket&& socket) {
  socket_ = std::make_unique<TcpSocketImpl>(std::move(socket));
}

//----------------------------------------
//
//----------------------------------------
Remote::Remote(asio::ip::tcp::socket socket): io_(), socket_(nullptr) {
  socket_ = std::make_unique<TcpSocketImpl>(std::move(socket));
}

//----------------------------------------
//
//----------------------------------------
Remote::Remote(asio::ssl::stream<asio::ip::tcp::socket> ssl_socket): io_(), socket_(nullptr) {
  socket_ = std::make_unique<TlsSocketImpl>(std::move(ssl_socket));
}

}
