#include "../include/Process.hpp"
#include "Helpers.hpp"

#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdexcept>
#include <vector>
#include <sstream>
#include <atomic>
#include <iostream>
#include <thread>


namespace cppwntools {

//----------------------------------------
//
//----------------------------------------
Process::Process(const std::string& command) {
    int stdin_pipe[2], stdout_pipe[2];

    if (pipe(stdin_pipe) < 0 || pipe(stdout_pipe) < 0) {
        throw std::runtime_error("pipe() failed");
    }

    pid_ = fork();
    if (pid_ == 0) {
        dup2(stdin_pipe[0], STDIN_FILENO);
        dup2(stdout_pipe[1], STDOUT_FILENO);

        ::close(stdin_pipe[1]);
        ::close(stdout_pipe[0]);

        execl("/bin/sh", "sh", "-c", command.c_str(), nullptr);
        _exit(1);
    }

    // Parent
    ::close(stdin_pipe[0]);
    ::close(stdout_pipe[1]);

    child_stdin_ = stdin_pipe[1];
    child_stdout_ = stdout_pipe[0];
}

//----------------------------------------
//
//----------------------------------------
void Process::send(const std::string& data) {
    write(child_stdin_, data.data(), data.size());
}

//----------------------------------------
//
//----------------------------------------
void Process::sendline(const std::string& data) {
    send(data + "\n");
}

//----------------------------------------
//
//----------------------------------------
int Process::getInputStream() {
  return child_stdin_;
}

//----------------------------------------
//
//----------------------------------------
int Process::getOutputStream() {
  return child_stdout_;
}

//----------------------------------------
//
//----------------------------------------
std::string Process::recv(std::size_t size) {
    std::vector<char> buf(size);
    ssize_t n = read(child_stdout_, buf.data(), size);
    return std::string(buf.begin(), buf.begin() + (n > 0 ? n : 0));
}

//----------------------------------------
//
//----------------------------------------
std::string Process::recvuntil(const std::string& delim) {
    std::string out;
    char ch;
    while (read(child_stdout_, &ch, 1) == 1) {
        out += ch;
        if (out.size() >= delim.size() &&
            out.substr(out.size() - delim.size()) == delim)
            break;
    }
    return out;
}

//----------------------------------------
//
//----------------------------------------
std::string Process::recvline() {
    return recvuntil("\n");
}

//----------------------------------------
//
//----------------------------------------
std::string Process::recvall() {
    std::string result;
    std::array<char, 4096> buf;
    ssize_t n;
    while ((n = read(child_stdout_, buf.data(), buf.size())) > 0) {
        result.append(buf.data(), n);
    }
    return result;
}

//----------------------------------------
//
//----------------------------------------
bool Process::is_alive() const {
    if (pid_ <= 0)
        return false;

    int status;
    pid_t result = waitpid(pid_, &status, WNOHANG);
    return result == 0; // still running
}

//----------------------------------------
//
//----------------------------------------
void Process::close() {
    if (child_stdin_ != -1) {
        ::close(child_stdin_);
        child_stdin_ = -1;
    }

    if (child_stdout_ != -1) {
        ::close(child_stdout_);
        child_stdout_ = -1;
    }

    if (pid_ > 0) {
        kill(pid_, SIGTERM);
        waitpid(pid_, nullptr, 0);
        pid_ = -1;
    }
}

//----------------------------------------
//
//----------------------------------------
void Process::interactive() {
    std::atomic<bool> running{true};
    std::thread input_thread(copy_stdin_to_stream, this, std::ref(running));
    std::thread output_thread(copy_stream_to_stdout, this, std::ref(running));

    input_thread.join();
    output_thread.join();
}

//----------------------------------------
//
//----------------------------------------
Process::~Process() {
    if(is_alive()) {
      close();
    }
}

}
