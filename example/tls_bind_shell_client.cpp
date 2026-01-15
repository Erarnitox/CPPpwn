#include <cpppwn.hpp>

//----------------------------------------
//
//----------------------------------------
int main() {
  using namespace cpppwn;

  Remote conn("127.0.0.1", 1337, true);
  conn.interactive();
}
