#include <cpppwn.hpp>
#include <print>

//----------------------------------------
//
//----------------------------------------
int main() {
  using namespace cpppwn;
  
  Server server(1337);

  while(true) {
    auto client = server.accept();
    
    std::println("New data: {}", client->recvline());

    client->sendline("Welcome!");
    client->close();
  }
}
