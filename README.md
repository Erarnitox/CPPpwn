<h1 style="font-family: 'Courier New', monospace; color: #ffffff;">
  <span style="color: #61afef;">cpp</span>pwn<span style="color: #98c379;">::>_</span>
</h1>
> Exploitation meets Networking

cpppwn is a modern C++ library that was initially inspired by the popular python libary "pwntools".
Where pwntools however is mainly focused on CTFs, cpppwn is a library that aims to provide helper functions and functionality for hacky, but every day tasks, like interacting with processes or web-servers.

## Features
- Process Interaction
- Memory Manipulation
- TCP Networking
- Bind and Reverse Shell
- TLS/SSL Connections
- HTTP/HTTPS Client and Server 
- TLS Fingerprint immitation
- REST Client and Server

## Installation
### Using CPM.cmake

The preferred method of installing this library is through the cpm package manager that you can find here:

> https://github.com/cpm-cmake/CPM.cmake

Once you have CPM "installed" you can use cpppwn like so:

```cmake
CPMAddPackage("gh:Erarnitox/CPPpwn#main")
target_link_libraries(your_executable PRIVATE cpppwn::cpppwn)
```

### Using CMake FetchContent

You can also install the library using the CMake built in function `FetchContent` directly, without using a package manager like so:

```cmake
include(FetchContent)

FetchContent_Declare(
    cpppwn 
    GIT_REPOSITORY https://github.com/Erarnitox/CPPpwn.git 
    GIT_TAG main
    GIT_PROGRESS TRUE
)

FetchContent_MakeAvailable(cpppwn)

target_link_libraries(your_executable PRIVATE cpppwn::cpppwn)
```

## Quick Start
```cpp
#include <cpppwn.hpp>
#include <print>

int main() {
    using namespace cpppwn;

    // connect to a TCP Server
    Remote conn("example.com", 1337);
    conn.sendline("Hello There!");
    std::println("Server Says: {}", conn.recvline());

    // launch a process
    Process proc("/bin/bash", {"/bin/bash"});
    proc.sendline("echo 'Hello There!'");
    std::println("Bash Says: {}", proc.recvline());

    // host a simple http server on port 8080
    HttpServer server(8080);

    server.get("/", [](const HttpRequest& req) {
        return HttpResponse().set_html("<h1>Hello There!</h1>");
    });

    server.start();
}
```

## Usage Examples
There are more practical and involved usage examples in the `example` Folder. 

## Contact
Please feel free to contact me:

> **X:** @erarnitox

> **Discord:** @erarnitox
