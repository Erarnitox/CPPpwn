#include <cpppwn.hpp>
#include <print>

//----------------------------------------
//
//----------------------------------------
int main() {
  using namespace cpppwn;

  Remote conn("127.0.0.1", 1337);
  connect_shell(conn);
}
