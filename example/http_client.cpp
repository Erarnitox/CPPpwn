#include <cpppwn.hpp>
#include <print>

//----------------------------------------
//
//----------------------------------------
int main() {
  using namespace cpppwn;
  
  HttpClient client;
  auto response = client.get("http://127.0.0.1:1337/");
  std::println("Response: {}", response.body);
}
