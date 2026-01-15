#include <cpppwn.hpp>
#include <print>

//----------------------------------------
//
//----------------------------------------
int main() {
  using namespace cpppwn;
  
  HttpClient client;
  auto response = client.get("https://127.0.0.1:31337/");
  std::println("Response: {}", response.body);
}
