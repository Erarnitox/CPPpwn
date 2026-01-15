#include <cpppwn.hpp>
#include <print>

//----------------------------------------
//
//----------------------------------------
int main() {
  using namespace cpppwn;
  
  auto [cert, key] = Server::generate_self_signed_cert();
  Server server(1337, { cert, key });

  while(true) {
    auto client = server.accept();
    
    std::println("New data: {}", client->recvline());

    client->sendline("Welcome!");
    client->close();
  }
}
