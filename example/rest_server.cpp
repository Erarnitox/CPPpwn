#include <cpppwn.hpp>

//----------------------------------------
//
//----------------------------------------
int main() {
  using namespace cpppwn;
  
  auto [cert, key] = Server::generate_self_signed_cert();
  RESTServer server(31337, { cert, key });

  server.get("/commands", [](const HttpRequest& req) {
    return HttpResponse()
    .set_json(R"([{"command":"something", "arg":"whatever"},{"command":"something2", "arg":"okay cool"}])");
  });

  server.start();
}
