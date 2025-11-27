#include <cpppwn.hpp>

//----------------------------------------
//
//----------------------------------------
int main() {
  using namespace cpppwn;
  
  HttpServer server(1337);

  server.get("/", [](const HttpRequest& req) {
    return HttpResponse().set_html("Hello There!");
  });

  server.start();
}
