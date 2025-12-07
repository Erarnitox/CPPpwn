#include <Shell.hpp>

#include <unistd.h>
#include <sys/wait.h>
#include <array>

namespace cpppwn {

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

//----------------------------------------
//
//----------------------------------------
void connect_popen(Stream& stream) {
    while(stream.is_alive()) {
        std::array<char, 128> buffer;
        const auto command = stream.recvline();
        std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
        while(fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
            stream.send(buffer.data());
        }
    }
}
}
