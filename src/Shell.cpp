#include "../include/Shell.hpp"

#include <unistd.h>
#include <thread>
#include <atomic>
#include <iostream>
#include <sys/wait.h>

namespace cppwntools {

//----------------------------------------
//
//----------------------------------------
void connect_shell(Stream& stream) {
    pid_t pid = fork();

    if (pid < 0) {
        throw std::runtime_error("fork failed");
    }

    if (pid == 0) {
        // Child process
        dup2(stream.getInputStream(), STDIN_FILENO);
        dup2(stream.getOutputStream(), STDOUT_FILENO);

        execl("/bin/sh", "sh", nullptr);
        _exit(1); 
    }

    // Parent can optionally wait or just return
    int status;
    waitpid(pid, &status, 0);
}
}
