#include "../include/Server.hpp"

namespace cppwntools {

//----------------------------------------
//
//----------------------------------------
Server::Server(uint16_t port)
    : acceptor_(io_, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port)) {}

//----------------------------------------
//
//----------------------------------------
std::unique_ptr<Stream> Server::accept() {
    asio::ip::tcp::socket socket(io_);
    acceptor_.accept(socket);
    auto remote = std::make_unique<Remote>("", 0);
    remote->swap_socket(std::move(socket)); 
    return remote;
}

}
