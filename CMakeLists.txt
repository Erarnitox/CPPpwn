cmake_minimum_required(VERSION 3.30)
project(cpppwn VERSION 0.0.1 LANGUAGES CXX)

option(CPPPWN_BUILD_EXAMPLE "Build the example program" OFF)

add_library(cpppwn
    src/Remote.cpp
    src/Process.cpp
    src/Server.cpp
    src/Shell.cpp
)

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

# ---------------------------------------------------------
# Fetch ASIO via CPM (header-only library, no real CMake)
# ---------------------------------------------------------
CPMAddPackage("gh:chriskohlhoff/asio#asio-1-34-2@1.34.2")

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

target_link_libraries(asio INTERFACE Threads::Threads)
target_link_libraries(cpppwn PRIVATE asio)

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
generate_export_header(cpppwn)

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
# Optional example program
# -------------------------------------
if (CPPPWN_BUILD_EXAMPLE)
    add_executable(example example/main.cpp)
    target_link_libraries(example PRIVATE cpppwn)
endif()

