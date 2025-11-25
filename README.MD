<h1 style="font-family: 'Courier New', monospace; color: #ffffff;">
  <span style="color: #61afef;">cpp</span>pwn<span style="color: #98c379;">::>_</span>
</h1>

cpppwn is a modern C++ library that was initially inspired by the popular python libary "pwntools".
Where pwntools however is mainly focused on CTFs, cpppwn is a library that aims to provide helper functions and functionality for hacky, but every day tasks, like interacting with processes or web-servers.

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

## Usage Examples
## Contribute
## Contact
