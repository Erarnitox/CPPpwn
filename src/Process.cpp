#include <Process.hpp>
#include "Helpers.hpp"

#include <unistd.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <fcntl.h>
#include <signal.h>
#include <dlfcn.h>

#include <stdexcept>
#include <system_error>
#include <vector>
#include <string>
#include <string_view>
#include <sstream>
#include <atomic>
#include <iostream>
#include <thread>
#include <fstream>
#include <cstring>
#include <filesystem>
#include <algorithm>
#include <memory>
#include <optional>
#include <array>
#include <span>

namespace fs = std::filesystem;

namespace cpppwn {

namespace {
    // RAII wrapper for file descriptors
class FileDescriptor {
  public:
    explicit FileDescriptor(int fd = -1) noexcept : fd_(fd) {}
        
    ~FileDescriptor() {
      if(fd_ >= 0) {
        ::close(fd_);
      }
    }
        
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
        
    FileDescriptor(FileDescriptor&& other) noexcept : fd_(other.fd_) {
      other.fd_ = -1;
    }
        
    FileDescriptor& operator=(FileDescriptor&& other) noexcept {
      if(this != &other) {
        if(fd_ >= 0) {
          ::close(fd_);
        }
        fd_ = other.fd_;
        other.fd_ = -1;
      }

      return *this;
    }
        
    [[nodiscard]] int get() const noexcept { return fd_; }
    [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }
        
    int release() noexcept {
      int fd = fd_;
      fd_ = -1;
      return fd;
    }
        
  private:
    int fd_;
};
    
//----------------------------------------
//
//----------------------------------------
class PtraceAttachment {
  public:
    explicit PtraceAttachment(pid_t pid) : pid_(pid), attached_(false) {
      if(ptrace(PTRACE_ATTACH, pid_, nullptr, nullptr) < 0) {
        throw std::system_error(errno, std::system_category(), "ptrace ATTACH failed");
      }
      attached_ = true;
            
      // Wait for process to stop
      int status;
      if(waitpid(pid_, &status, 0) < 0) {
        ptrace(PTRACE_DETACH, pid_, nullptr, nullptr);
        throw std::system_error(errno, std::system_category(), "waitpid after attach failed");
      }
    }
        
    ~PtraceAttachment() {
      if(attached_) {
        ptrace(PTRACE_DETACH, pid_, nullptr, nullptr);
      }
    }
        
    PtraceAttachment(const PtraceAttachment&) = delete;
    PtraceAttachment& operator=(const PtraceAttachment&) = delete;
        
    PtraceAttachment(PtraceAttachment&&) = delete;
    PtraceAttachment& operator=(PtraceAttachment&&) = delete;
        
  private:
    pid_t pid_;
    bool attached_;
};
    
//----------------------------------------
//
//----------------------------------------
std::optional<pid_t> findProcessByName(std::string_view process_name) {
  const fs::path proc_dir{"/proc"};
        
  if(not fs::exists(proc_dir) || not fs::is_directory(proc_dir)) {
    throw std::runtime_error("Cannot access /proc directory");
  }
        
  for(const auto& entry : fs::directory_iterator(proc_dir)) {
    if(not entry.is_directory()) continue;
    const auto dirname = entry.path().filename().string();
            
    // Check if directory name is numeric (PID)
    if(dirname.empty() || not std::all_of(dirname.begin(), dirname.end(), ::isdigit)) {
      continue;
    }
            
    const pid_t pid = std::stoi(dirname);
    if(pid <= 0) continue;
            
    // Read cmdline
    const auto cmdline_path = entry.path() / "cmdline";
    std::ifstream cmdline_file(cmdline_path);
    if(not cmdline_file.is_open()) continue;
            
    std::string cmdline;
    std::getline(cmdline_file, cmdline, '\0');
            
    if(cmdline.empty()) continue;
            
    // Extract basename from full path
    const fs::path cmd_path{cmdline};
    const auto basename = cmd_path.filename().string();
            
    if(basename == process_name) {
      return pid;
    }
  }
        
  return std::nullopt;
}
    
//----------------------------------------
//
//----------------------------------------
std::string readFileContent(const fs::path& path) {
  std::ifstream file(path);
  if(not file.is_open()) {
    throw std::system_error(errno, std::system_category(), "Cannot open " + path.string());
  }
  return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}
    
//----------------------------------------
// Parse byte pattern with wildcards
//----------------------------------------
std::vector<std::optional<std::byte>> parseSignature(std::string_view signature) {
  std::vector<std::optional<std::byte>> pattern;
  std::istringstream iss{std::string(signature)};
  std::string token;
        
  while(iss >> token) {
    if(token == "?" || token == "??") {
      pattern.push_back(std::nullopt);
    } else {
      pattern.push_back(std::byte{static_cast<unsigned char>(std::stoi(token, nullptr, 16))});
    }
  }
        
  return pattern;
}
    
//----------------------------------------
// Match Pattern in Buffer
//----------------------------------------
bool matchPattern(std::span<const std::byte> buffer, std::span<const std::optional<std::byte>> pattern) {
  if(buffer.size() < pattern.size()) return false;
        
    for(size_t i = 0; i < pattern.size(); ++i) {
      if(pattern[i].has_value() && buffer[i] != *pattern[i]) {
        return false;
      }
    }
    return true;
  }
}

//----------------------------------------
// Attach to a running process by name
//----------------------------------------
Process::Process(const std::string& process_name) 
  : process_name_(process_name), 
    process_handle_(-1), 
    child_stdin_(-1), 
    child_stdout_(-1), 
    pid_(-1) {
    
  auto pid = findProcessByName(process_name);
  if(not pid.has_value()) {
    throw std::runtime_error("Process not found: " + process_name);
  }
    
  pid_ = pid.value();

  // Try to attach to the process's terminal (TTY)
  // First, find the terminal device the process is using
  const fs::path fd_dir = fs::path("/proc") / std::to_string(pid_) / "fd";
    
  if(not fs::exists(fd_dir)) {
    // Process exists but we can't access fd directory_iterator
    // continue without TTY
    return;
  }
    
  std::optional<fs::path> tty_path;
    
  try {
    // Look for stdin/stdout symbolic links in /proc/[pid]/fd/
    for(const auto& entry : fs::directory_iterator(fd_dir)) {
      if(not entry.is_symlink()) continue;
            
      try {
        const auto target = fs::read_symlink(entry.path());
        const auto target_str = target.string();
                
        if(target_str.find("/dev/pts/") != std::string::npos ||
            target_str.find("/dev/tty") != std::string::npos) {
              tty_path = target;
              break;
        }
      } catch (const fs::filesystem_error&) {
        // Permission denied or invalid symlink, skip
        continue;
      }
    }
  } catch (const fs::filesystem_error&) {
    // Can't read fd directory, continue without TTY
    return;
  }
    
  if(not tty_path) {
    // Process doesn't have a TTY attached (daemon, background process, etc.)
    return;
  }
    
  // Try to open the TTY for read/write
  // Note: This requires appropriate permissions
  const int tty_fd = open(tty_path->c_str(), O_RDWR | O_NOCTTY);
  if(tty_fd < 0) {
    // Can't open TTY (permission denied, etc.) - not a fatal error
    // The process is still attached, just without TTY I/O
    return;
  }
    
  // Successfully opened the TTY
  child_stdin_ = dup(tty_fd);   // For writing to the process
  child_stdout_ = dup(tty_fd);  // For reading from the process
  ::close(tty_fd);
    
  if(child_stdin_ < 0 || child_stdout_ < 0) {
    // Failed to duplicate file descriptor
    if(child_stdin_ >= 0) {
      ::close(child_stdin_);
      child_stdin_ = -1;
    }

    if(child_stdout_ >= 0) {
      ::close(child_stdout_);
      child_stdout_ = -1;
    }
  }
}

//----------------------------------------
// Safe constructor using execvp
//----------------------------------------
Process::Process(const std::string& executable, 
                 const std::vector<std::string>& args) 
  : process_name_(executable), 
    process_handle_(-1), 
    child_stdin_(-1), 
    child_stdout_(-1), 
    pid_(-1) {
    
  std::array<int, 2> stdin_pipe;
  std::array<int, 2> stdout_pipe;

  if(pipe(stdin_pipe.data()) < 0 || pipe(stdout_pipe.data()) < 0) {
    throw std::system_error(errno, std::system_category(), "pipe() failed");
  }

  pid_ = fork();
    
  if(pid_ == 0) {
    // Child process
    dup2(stdin_pipe[0], STDIN_FILENO);
    dup2(stdout_pipe[1], STDOUT_FILENO);
    dup2(stdout_pipe[1], STDERR_FILENO);

    ::close(stdin_pipe[1]);
    ::close(stdout_pipe[0]);

    // Build argv array for execvp
    std::vector<char*> argv;
    argv.reserve(args.size() + 1);

    for(const auto& arg : args) {
      argv.push_back(const_cast<char*>(arg.c_str()));
    }
    argv.push_back(nullptr);

    execvp(executable.c_str(), argv.data());
    _exit(1);
  }

  if(pid_ < 0) {
    ::close(stdin_pipe[0]);
    ::close(stdin_pipe[1]);
    ::close(stdout_pipe[0]);
    ::close(stdout_pipe[1]);
    throw std::system_error(errno, std::system_category(), "fork() failed");
  }

  // Parent process
  ::close(stdin_pipe[0]);
  ::close(stdout_pipe[1]);

  child_stdin_ = stdin_pipe[1];
  child_stdout_ = stdout_pipe[0];
}

//----------------------------------------
// Send data to process stdin
//----------------------------------------
void Process::send(const std::string& data) {
  if(child_stdin_ == -1) {
    throw std::runtime_error("Cannot send data: process not started with pipes");
  }
    
  const ssize_t written = write(child_stdin_, data.data(), data.size());
  if(written < 0) {
    throw std::system_error(errno, std::system_category(), "write() failed");
  }
}

//----------------------------------------
// Send line to process stdin
//----------------------------------------
void Process::sendline(const std::string& data) {
  send(data + "\n");
}

//----------------------------------------
// Get input stream file descriptor
//----------------------------------------
int Process::getInputStream() noexcept {
  return child_stdin_;
}

//----------------------------------------
// Get output stream file descriptor
//----------------------------------------
int Process::getOutputStream() noexcept {
  return child_stdout_;
}

//----------------------------------------
// Receive fixed amount of data
//----------------------------------------
std::string Process::recv(std::size_t size) {
  if(child_stdout_ == -1) {
    throw std::runtime_error("Cannot receive data: process not started with pipes");
  }
    
  std::vector<char> buf(size);
  const ssize_t n = read(child_stdout_, buf.data(), size);
    
  if(n < 0) {
    throw std::system_error(errno, std::system_category(), "read() failed");
  }
    
  return std::string(buf.begin(), buf.begin() + n);
}

//----------------------------------------
// Receive until delimiter
//----------------------------------------
std::string Process::recvuntil(const std::string& delim) {
  if(child_stdout_ == -1) {
    throw std::runtime_error("Cannot receive data: process not started with pipes");
  }
    
  std::string out;
  out.reserve(1024); // Pre-allocate for efficiency
    
  char ch;
  while(read(child_stdout_, &ch, 1) == 1) {
    out += ch;
        
    if(out.size() >= delim.size() &&
      std::string_view(out).substr(out.size() - delim.size()) == delim) {
      break;
    }
  }
    
  return out;
}

//----------------------------------------
// Receive line
//----------------------------------------
std::string Process::recvline() {
  return recvuntil("\n");
}

//----------------------------------------
// Receive all available data
//----------------------------------------
std::string Process::recvall() {
  if(child_stdout_ == -1) {
    throw std::runtime_error("Cannot receive data: process not started with pipes");
  }
    
  std::string result;
  std::array<char, 4096> buf;
  ssize_t n;
    
  while((n = read(child_stdout_, buf.data(), buf.size())) > 0) {
    result.append(buf.data(), n);
  }
    
  return result;
}

//----------------------------------------
// Check if process is alive
//----------------------------------------
bool Process::is_alive() const noexcept {
  if(pid_ < 1) return false;

  int status;
  const pid_t result = waitpid(pid_, &status, WNOHANG);
  return result == 0; // still running
}

//----------------------------------------
// Close process and cleanup
//----------------------------------------
void Process::close() {
  if(child_stdin_ != -1) {
    ::close(child_stdin_);
    child_stdin_ = -1;
  }

  if(child_stdout_ != -1) {
    ::close(child_stdout_);
    child_stdout_ = -1;
  }

  if(pid_ > 0) {
    kill(pid_, SIGTERM);
    waitpid(pid_, nullptr, 0);
    pid_ = -1;
  }
}

//----------------------------------------
// Interactive mode
//----------------------------------------
void Process::interactive() {
  std::atomic<bool> running{true};
  std::thread input_thread(copy_stdin_to_stream, this, std::ref(running));
  std::thread output_thread(copy_stream_to_stdout, this, std::ref(running));

  input_thread.join();
  output_thread.join();
}

//----------------------------------------
// Destructor
//----------------------------------------
Process::~Process() {
  if(is_alive()) {
    close();
  }
}

//----------------------------------------
// Find signature/pattern in process memory
//----------------------------------------
std::optional<address_t> Process::findSignature(const std::string& signature) {
  if(pid_ < 1) {
    throw std::runtime_error("No valid process");
  }
    
  // Parse signature pattern
  const auto pattern = parseSignature(signature);
  if(pattern.empty()) {
    return std::nullopt;
  }
    
  // Read /proc/[pid]/maps to find memory regions
  const fs::path maps_path = fs::path("/proc") / std::to_string(pid_) / "maps";
  std::ifstream maps_file(maps_path);
    
  if(not maps_file) {
    throw std::system_error(errno, std::system_category(), "Cannot open " + maps_path.string());
  }
    
  const fs::path mem_path = fs::path("/proc") / std::to_string(pid_) / "mem";
    
  std::string line;
  while(std::getline(maps_file, line)) {
    std::istringstream line_stream(line);
    std::string addr_range, perms;
    line_stream >> addr_range >> perms;
        
    // Only search readable regions
    if(perms[0] != 'r') continue;
        
    // Parse address range
    const size_t dash_pos = addr_range.find('-');
    const address_t start = std::stoull(addr_range.substr(0, dash_pos), nullptr, 16);
    const address_t end = std::stoull(addr_range.substr(dash_pos + 1), nullptr, 16);
    const size_t region_size = end - start;
        
    // Read memory region
    FileDescriptor mem_fd(open(mem_path.c_str(), O_RDONLY));
    if(not mem_fd.valid())
      continue;
        
    std::vector<std::byte> buffer(region_size);
    if(pread(mem_fd.get(), buffer.data(), region_size, start) != static_cast<ssize_t>(region_size)) {
      continue;
    }
        
    // Search for pattern using sliding window
    for (size_t i{ 0 }; i <= buffer.size() - pattern.size(); ++i) {
      std::span<const std::byte> window(buffer.data() + i, pattern.size());
      if(matchPattern(window, pattern)) {
        return start + i;
      }
    }
  }
    
  return std::nullopt;
}

//----------------------------------------
// Write to process memory
//----------------------------------------
void Process::writeMemory(const address_t address, const buffer_t& buffer) {
  if(pid_ < 1) {
    throw std::runtime_error("No valid process");
  }
    
  const fs::path mem_path = fs::path("/proc") / std::to_string(pid_) / "mem";
  FileDescriptor mem_fd(open(mem_path.c_str(), O_WRONLY));
    
  if(not mem_fd.valid()) {
    throw std::system_error(errno, std::system_category(), 
      "Cannot open " + mem_path.string()
    );
  }
    
  const ssize_t written = pwrite(mem_fd.get(), buffer.data(), buffer.size(), address);
    
  if(written != static_cast<ssize_t>(buffer.size())) {
    throw std::system_error(errno, std::system_category(), 
      "Failed to write memory at 0x" + std::to_string(address)
    );
  }
}

//----------------------------------------
// Read from process memory
//----------------------------------------
buffer_t Process::readMemory(const address_t address, size_t size) {
  if(pid_ < 1) {
    throw std::runtime_error("No valid process");
  }
    
  const fs::path mem_path = fs::path("/proc") / std::to_string(pid_) / "mem";
  FileDescriptor mem_fd(open(mem_path.c_str(), O_RDONLY));
    
  if(not mem_fd.valid()) {
    throw std::system_error(errno, std::system_category(), "Cannot open " + mem_path.string());
  }
    
  buffer_t buffer(size);
  const ssize_t bytes_read = pread(mem_fd.get(), buffer.data(), size, address);
    
  if(bytes_read != static_cast<ssize_t>(size)) {
    throw std::system_error(errno, std::system_category(), 
        "Failed to read memory at 0x" + std::to_string(address)
    );
  }
    
  return buffer;
}

//----------------------------------------
// Get base address of a module
//----------------------------------------
address_t Process::getBaseAddress(const std::string& module_name) {
  if(pid_ < 1) {
    throw std::runtime_error("No valid process");
  }
    
  const fs::path maps_path = fs::path("/proc") / std::to_string(pid_) / "maps";
  std::ifstream maps_file(maps_path);
    
  if(not maps_file) {
    throw std::system_error(errno, std::system_category(), "Cannot open " + maps_path.string());
  }
    
  std::string line;

  while(std::getline(maps_file, line)) {
    bool is_target = false;
        
    if(module_name.empty()) {
      // Find first executable mapping
      std::istringstream iss(line);
      std::string addr, perms;
      iss >> addr >> perms;
      is_target = (perms.find('x') != std::string::npos);
    } else {
      is_target = (line.find(module_name) != std::string::npos);
    }
        
    if(is_target) {
      std::istringstream iss(line);
      std::string addr_range;
      iss >> addr_range;
            
      const size_t dash_pos = addr_range.find('-');
      return std::stoull(addr_range.substr(0, dash_pos), nullptr, 16);
    }
  }
    
  throw std::runtime_error("Module not found: " + (module_name.empty() ? "executable" : module_name));
}

//----------------------------------------
// Load library into target process using ptrace
//----------------------------------------
void Process::loadLibrary(const std::string& path) {
  if(pid_ < 1) {
    throw std::runtime_error("No valid process");
  }
    
  // Verify library exists using std::filesystem
  const fs::path lib_path{path};
  if(not fs::exists(lib_path)) {
    throw std::runtime_error("Library not found: " + path);
  }
    
  if(not fs::is_regular_file(lib_path)) {
    throw std::runtime_error("Not a regular file: " + path);
  }
    
  // RAII-based ptrace attachment
  PtraceAttachment ptrace_guard(pid_);
    
  // Save original registers
  struct user_regs_struct orig_regs, regs;
  if(ptrace(PTRACE_GETREGS, pid_, nullptr, &orig_regs) < 0) {
    throw std::system_error(errno, std::system_category(), "ptrace GETREGS failed");
  }
  regs = orig_regs;
    
  // Find libc base address
  const fs::path maps_path = fs::path("/proc") / std::to_string(pid_) / "maps";
  std::ifstream maps_file(maps_path);
    
  if(not maps_file.is_open()) {
    throw std::system_error(errno, std::system_category(), "Cannot open " + maps_path.string());
  }
    
  address_t libc_base = 0;
  std::string line;
    
  while(std::getline(maps_file, line)) {
    if(line.find("libc") != std::string::npos && 
      line.find("r-xp") != std::string::npos) {
      std::istringstream iss(line);
      std::string addr_range;
      iss >> addr_range;
      const size_t dash = addr_range.find('-');
      libc_base = std::stoull(addr_range.substr(0, dash), nullptr, 16);
      break;
    }
  }
    
  if(libc_base < 1) {
    throw std::runtime_error("Could not find libc in target process");
  }
    
  // Get dlopen address using RAII for dlopen handle
  struct DlopenHandle {
    void* handle;
    explicit DlopenHandle(const char* name) : handle(dlopen(name, RTLD_LAZY)) {
      if(not handle) {
        throw std::runtime_error("Could not load local libc: " + std::string(dlerror()));
      }
    }

    ~DlopenHandle() { 
      if(handle) 
        dlclose(handle); 
    }

    DlopenHandle(const DlopenHandle&) = delete;
    DlopenHandle& operator=(const DlopenHandle&) = delete;
  };
    
  DlopenHandle local_libc("libc.so.6");
    
  void* local_dlopen = dlsym(local_libc.handle, "__libc_dlopen_mode");
  if(not local_dlopen) {
    local_dlopen = dlsym(local_libc.handle, "dlopen");
  }
  
  if(not local_dlopen) {
    throw std::runtime_error("Could not find dlopen symbol: " + std::string(dlerror()));
  }
    
  // Calculate dlopen offset
  const fs::path self_maps_path{"/proc/self/maps"};
  std::ifstream self_maps(self_maps_path);
  address_t self_libc_base = 0;
    
  while(std::getline(self_maps, line)) {
    if(line.find("libc") != std::string::npos && line.find("r-xp") != std::string::npos) {
      std::istringstream iss(line);
      std::string addr_range;
      iss >> addr_range;
      const size_t dash = addr_range.find('-');
      self_libc_base = std::stoull(addr_range.substr(0, dash), nullptr, 16);
      break;
    }
  }
    
  if(self_libc_base < 1) {
    throw std::runtime_error("Could not determine libc base in current process");
  }
    
  const address_t dlopen_offset = reinterpret_cast<address_t>(local_dlopen) - self_libc_base;
  const address_t dlopen_addr = libc_base + dlopen_offset;
    
  // Setup memory for library path
  const address_t stack_addr = regs.rsp - 0x1000;
  const std::string lib_path_str = lib_path.string();
  const size_t path_len = lib_path_str.length() + 1;
    
  const fs::path mem_path = fs::path("/proc") / std::to_string(pid_) / "mem";
  FileDescriptor mem_fd(open(mem_path.c_str(), O_RDWR));
    
  if(not mem_fd.valid()) {
    throw std::system_error(errno, std::system_category(), "Cannot open " + mem_path.string());
  }
    
  // Write path string
  if(pwrite(mem_fd.get(), lib_path_str.c_str(), path_len, stack_addr) != static_cast<ssize_t>(path_len)) {
    throw std::system_error(errno, std::system_category(), "Failed to write library path to process memory");
  }
    
  // Setup registers for dlopen call (x86_64 calling convention)
  regs.rdi = stack_addr;                  // First argument: filename
  regs.rsi = RTLD_LAZY | RTLD_GLOBAL;     // Second argument: flags
  regs.rip = dlopen_addr;                 // Jump to dlopen
    
  // Setup return address with trap instruction
  constexpr address_t return_addr_offset = 0x100;
  const address_t return_addr = stack_addr + return_addr_offset;
  constexpr uint64_t trap = 0xCCCCCCCCCCCCCCCC; // INT3 instructions
    
  if(pwrite(mem_fd.get(), &trap, sizeof(trap), return_addr) != sizeof(trap)) {
    throw std::system_error(errno, std::system_category(), "Failed to write trap instruction");
  }
    
  regs.rsp = return_addr - 8;
  if(pwrite(mem_fd.get(), &return_addr, sizeof(return_addr), regs.rsp) != sizeof(return_addr)) {
    throw std::system_error(errno, std::system_category(), "Failed to write return address");
  }
    
  // Set modified registers and execute
  if(ptrace(PTRACE_SETREGS, pid_, nullptr, &regs) < 0) {
    throw std::system_error(errno, std::system_category(), "ptrace SETREGS failed");
  }
    
  if(ptrace(PTRACE_CONT, pid_, nullptr, nullptr) < 0) {
    throw std::system_error(errno, std::system_category(), "ptrace CONT failed");
  }
    
  // Wait for trap
  int status;
  waitpid(pid_, &status, 0);
    
  // Check dlopen return value
  struct user_regs_struct result_regs;
  if(ptrace(PTRACE_GETREGS, pid_, nullptr, &result_regs) < 0) {
    throw std::system_error(errno, std::system_category(), "ptrace GETREGS failed after call");
  }
    
  if(result_regs.rax == 0) {
    // Restore registers before throwing
    ptrace(PTRACE_SETREGS, pid_, nullptr, &orig_regs);
    throw std::runtime_error("dlopen returned NULL - library load failed");
  }
    
  // Restore original registers
  if(ptrace(PTRACE_SETREGS, pid_, nullptr, &orig_regs) < 0) {
    throw std::system_error(errno, std::system_category(), "ptrace SETREGS restore failed");
  }
}

} // namespace cpppwn
