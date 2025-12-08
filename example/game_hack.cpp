#include <cpppwn.hpp>

#include <print>

int main() {
  using namespace cpppwn;
  
  Process game("simple_game");
  address_t points_offset = 0x271d0; // this might need to be updated for your build

  auto game_base = game.getBaseAddress();
  address_t points_address = game_base + points_offset;

  std::println("Games Base Address is [0x{:x}]", game_base);
  std::println("Points Address is [0x{:x}]", points_address);

  auto points_value = game.readValue<int>(points_address);

  std::println("Current Points: {}", points_value);

  // increment points
  points_value += 10000;
  game.writeValue<decltype(points_value)>(points_address, points_value);
}