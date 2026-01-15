cmake_minimum_required(VERSION 3.30)
project(cpppwn VERSION 0.0.1 LANGUAGES CXX)

option(CPPPWN_BUILD_EXAMPLE "Build the example program" OFF)

add_library(cpppwn STATIC
    "src/Remote.cpp"
    "src/Process.cpp"
    "src/Server.cpp"
    "src/Shell.cpp"
    "src/HttpClient.cpp"
    "src/HttpServer.cpp"
    "src/HttpUtils.cpp"
    "src/RESTClient.cpp"
    "src/RESTServer.cpp"
    "src/Pattern.cpp"

    # includes for some IDEs
    "include/Remote.hpp"
    "include/Process.hpp"
    "include/Server.hpp"
    "include/Shell.hpp"
    "include/HttpClient.hpp"
    "include/HttpServer.hpp"
    "include/HttpUtils.hpp"
    "include/RESTClient.hpp"
    "include/RESTServer.hpp"
    "include/Pattern.hpp"
    "include/cpppwn.hpp"
)
add_library(cpppwn::cpppwn ALIAS cpppwn)

target_compile_features(cpppwn PUBLIC cxx_std_23)

set_target_properties(cpppwn PROPERTIES
    CXX_EXTENSIONS OFF
    SOVERSION 1
    VERSION ${PROJECT_VERSION}
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)

# Export compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# -------------------------------------
# Dependencies
# -------------------------------------
include(GNUInstallDirs)
include(cmake/CPM.cmake)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# ---------------------------------------------------------
# Fetch ASIO via CPM (header-only library)
# ---------------------------------------------------------
CPMAddPackage("gh:chriskohlhoff/asio#asio-1-36-0@1.36.0")

# Create a clean Asio target ourselves to avoid leaking paths
add_library(asio INTERFACE)

target_include_directories(asio SYSTEM INTERFACE
    $<BUILD_INTERFACE:${asio_SOURCE_DIR}/asio/include>
    $<INSTALL_INTERFACE:include>
)

target_compile_definitions(asio INTERFACE
    ASIO_STANDALONE
    ASIO_NO_DEPRECATED
)

target_link_libraries(asio INTERFACE 
  Threads::Threads
  OpenSSL::SSL
  OpenSSL::Crypto
)

CPMAddPackage(
  NAME glaze
  GITHUB_REPOSITORY stephenberry/glaze
  GIT_TAG v6.1.0
)

CPMAddPackage(
    NAME curl
    GITHUB_REPOSITORY curl/curl
    GIT_TAG curl-8_17_0
    OPTIONS
        "CURL_USE_OPENSSL ON"
        "CMAKE_USE_LIBSSH2 OFF" # maybe useful for reverse shells and other traffic tunneling tricks later
        "BUILD_CURL_EXE OFF"
        "CURL_ZLIB ON"
        "BUILD_SHARED_LIBS OFF"
        "BUILD_STATIC_LIBS ON"
)

# -------------------------------------
# Link libraries (order matters!)
# -------------------------------------
# Changed from PRIVATE to PUBLIC for transitive dependencies
target_link_libraries(cpppwn PUBLIC
    asio
    CURL::libcurl
    glaze::glaze
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    ${CMAKE_DL_LIBS}
)

# -------------------------------------
# Public include interface
# -------------------------------------
target_include_directories(cpppwn
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# -------------------------------------
# Export header generation
# -------------------------------------
include(GenerateExportHeader)
generate_export_header(cpppwn
    EXPORT_FILE_NAME ${CMAKE_CURRENT_BINARY_DIR}/cpppwn_export.h
)

# Install the generated export header
install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/cpppwn_export.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

target_include_directories(cpppwn PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
)

install(
    TARGETS cpppwn asio
    EXPORT cpppwnTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(
    DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Export target file for consumers via find_package(cpppwn)
install(
    EXPORT cpppwnTargets
    FILE cpppwnTargets.cmake
    NAMESPACE cpppwn::
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/cpppwn"
)

# -------------------------------------
# Package config
# -------------------------------------
include(CMakePackageConfigHelpers)

write_basic_package_version_file(
    cpppwnConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/Config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/cpppwnConfig.cmake
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/cpppwn"
)

install(
    FILES "${CMAKE_CURRENT_BINARY_DIR}/cpppwnConfig.cmake"
          "${CMAKE_CURRENT_BINARY_DIR}/cpppwnConfigVersion.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/cpppwn"
)

# -------------------------------------
# Optional example programs
# -------------------------------------
if (CPPPWN_BUILD_EXAMPLE)
  add_subdirectory(example)
endif()
