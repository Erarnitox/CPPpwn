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

  auto points_value_buffer = game.readMemory(points_address, 4);
  auto points_value = *reinterpret_cast<int*>(&(*points_value_buffer.begin()));

  std::println("Current Points: {}", points_value);

  // increment points
  points_value += 10000;

  buffer_t hacked_value_buffer;
  hacked_value_buffer.reserve(sizeof(points_value));
  auto points_value_iter = reinterpret_cast<char*>(&points_value);

  for(size_t i{ 0 }; i < sizeof(points_value); ++i) {
    hacked_value_buffer.push_back(*(points_value_iter+i));
  }
  game.writeMemory(points_address, hacked_value_buffer);
}