#include <cpppwn.hpp>

//----------------------------------------
//
//----------------------------------------
int main() {
  using namespace cpppwn;
  
  auto [cert, key] = Server::generate_self_signed_cert();
  HttpServer server(31337, { cert, key });

  server.get("/", [](const HttpRequest& req) {
    return HttpResponse().set_html("Hello There!");
  });

  server.start();
}
