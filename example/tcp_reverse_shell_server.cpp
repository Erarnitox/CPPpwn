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
    client->interactive();
  }
}
