#include <cpppwn.hpp>
#include <print>

//----------------------------------------
//
//----------------------------------------
struct Command {
  std::string command;
  std::string arg;
};

//----------------------------------------
//
//----------------------------------------
using Commands = std::vector<Command>;

//----------------------------------------
//
//----------------------------------------
int main() {
  using namespace cpppwn;
  
  RESTClient client("https://127.0.0.1:31337/");

  auto commands = client.get<Commands>("commands");

  for(const auto& c : commands) {
    std::println("Command: {}, Arg: {}", c.command, c.arg);
  }
}
