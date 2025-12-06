
# General example
add_executable(example main.cpp)
target_link_libraries(example PRIVATE cpppwn)

# Simple TCP client
add_executable(tcp_client tcp_client.cpp)
target_link_libraries(tcp_client PRIVATE cpppwn)

# Simple TCP server 
add_executable(tcp_server tcp_server.cpp)
target_link_libraries(tcp_server PRIVATE cpppwn)

# TCP reverse shell
add_executable(tcp_reverse_shell_server tcp_reverse_shell_server.cpp)
target_link_libraries(tcp_reverse_shell_server PRIVATE cpppwn)

# TCP reverse shell client
add_executable(tcp_reverse_shell_client tcp_reverse_shell_client.cpp)
target_link_libraries(tcp_reverse_shell_client PRIVATE cpppwn)

# TCP bind shell server
add_executable(tcp_bind_shell_server tcp_bind_shell_server.cpp)
target_link_libraries(tcp_bind_shell_server PRIVATE cpppwn)

# TCP bind shell client
add_executable(tcp_bind_shell_client tcp_bind_shell_client.cpp)
target_link_libraries(tcp_bind_shell_client PRIVATE cpppwn)

# Simple TLS client
add_executable(tls_client tls_client.cpp)
target_link_libraries(tls_client PRIVATE cpppwn)

# Simple TLS server 
add_executable(tls_server tls_server.cpp)
target_link_libraries(tls_server PRIVATE cpppwn)

# simple HTTP server 
add_executable(http_server http_server.cpp)
target_link_libraries(http_server PRIVATE cpppwn)

# simple HTTP client 
add_executable(http_client http_client.cpp)
target_link_libraries(http_client PRIVATE cpppwn)

# simple HTTPS server 
add_executable(https_server https_server.cpp)
target_link_libraries(https_server PRIVATE cpppwn)

########################################################
## TODO: The things below are not working yet

# simple HTTPS client 
add_executable(https_client https_client.cpp)
target_link_libraries(https_client PRIVATE cpppwn)

# TLS reverse shell
#add_executable(tls_reverse_shell tls_reverse_shell.cpp)
#target_link_libraries(tls_reverse_shell PRIVATE cpppwn)

# TLS bind shell
#add_executable(tls_bind_shell tls_bind_shell.cpp)
#target_link_libraries(tls_bind_shell PRIVATE cpppwn)

# TLS bind shell server
add_executable(tls_bind_shell_server tls_bind_shell_server.cpp)
target_link_libraries(tls_bind_shell_server PRIVATE cpppwn)

# TLS bind shell client
add_executable(tls_bind_shell_client tls_bind_shell_client.cpp)
target_link_libraries(tls_bind_shell_client PRIVATE cpppwn)
