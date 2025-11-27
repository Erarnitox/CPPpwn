#include "Stream.hpp"

#include <atomic>
#include <thread>
#include <vector>

namespace cpppwn {
namespace {

constexpr std::size_t kBufferSize = 4096;

//----------------------------------------
// copies data from source stream to destination stream until stopped.
// on exit, closes dest to unblock the other thread reading from it.
//----------------------------------------
void copy_stream_to_stream(Stream* source, Stream* dest, std::atomic<bool>& running) noexcept {
  try {
    while (running.load(std::memory_order_acquire) && source->is_alive()) {
      std::string data = source->recv(kBufferSize);
      if (data.empty()) {
        // clean disconnect if we get nothing back
        break;
      }
      dest->send(data);
    }
  } catch (...) {
    // swallow the error. usually just a socket disconnect
  }

  // tell the other thread the party is over
  running.store(false, std::memory_order_release);

  // nuke the destination to force the other thread out of its blocking recv
  try {
    dest->close();
  } catch (...) {
    // were tearing down anyway, ignore errors
  }
}

} // anonymous namespace

//----------------------------------------
//
//----------------------------------------
void bridge(Stream& a, Stream& b) {
  std::atomic<bool> running{true};

  // thread 1: a -> b
  std::thread a_to_b_thread(copy_stream_to_stream, &a, &b, std::ref(running));

  // thread 2: b -> a
  std::thread b_to_a_thread(copy_stream_to_stream, &b, &a, std::ref(running));

  // block until both threads complete
  if (a_to_b_thread.joinable()) {
    a_to_b_thread.join();
  }
  if (b_to_a_thread.joinable()) {
    b_to_a_thread.join();
  }
}

} // namespace cpppwn
