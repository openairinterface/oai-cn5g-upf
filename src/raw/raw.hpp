#ifndef FILE_RAW_HPP_SEEN
#define FILE_RAW_HPP_SEEN

#include "conversions.hpp"
#include "endpoint.hpp"
#include "itti.hpp"
#include "thread_sched.hpp"

#include <folly/MPMCQueue.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <sys/socket.h>

#include <iostream>
#include <map>
#include <memory>
#include <stdint.h>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include <chrono>
#include <ctime>
#include <stdexcept>
#include <linux/ip.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <netinet/ether.h> // for ether_ntoa()

class raw_application {
 public:
  virtual void handle_receive(
      const char* recv_buffer, const std::size_t bytes_transferred);
  virtual void start_receive(
      raw_application* gtp_stack,
      const util::thread_sched_params& sched_params);
};
class raw_server;

typedef struct raw_packet_q_item_s {
  char* buffer;
  endpoint r_endpoint;
  size_t size;
} raw_packet_q_item_t;

typedef struct iovec_q_item_s {
  struct iovec msg_iov;
  struct msghdr msg;
} iovec_q_item_t;

class raw_server {
#define RAW_RECV_BUFFER_SIZE 8192
#define ROOM_FOR_ENCAP 64
 public:
  raw_server(const char* ifname)
      : app_(nullptr),
        free_pool_(nullptr),
        work_pool_(nullptr) {
    socket_raw = create_socket(ifname);
    if (socket_raw > 0) {
      Logger::raw().debug("raw_server::raw_server(%s)", ifname);
    } else {
      Logger::raw().error("raw_server::raw_server(%s)", ifname);
      std::this_thread::sleep_for(std::chrono::milliseconds(500));
      throw std::system_error(
          socket_raw, std::generic_category(), "RAW socket creation failed!");
    }
  }

  ~raw_server() {
    close(socket_raw);
    // TODO delete/release elements in  the pool
    delete free_pool_;
    delete work_pool_;
    free(recv_buffer_alloc_);
    // free(raw_packet_q_item_alloc_);
  }

  void raw_read_loop(const util::thread_sched_params& thread_sched_params);
  void raw_worker_loop(
      const int id, const util::thread_sched_params& sched_params);

  void send(const char* sendbuff, const ssize_t len) {
    int bytes_sent;
    if ((bytes_sent = write(socket_raw, sendbuff, len)) < 0) {
      Logger::raw().error(
          "write fd %d failed rc=%d:%s", socket_raw, bytes_sent, strerror(errno));
    }
  }

  void start_receive(
      raw_application* gtp_stack,
      const util::thread_sched_params& sched_params);
  void stop(void);

 protected:
  int create_socket(const char* ifname);

  // void handle_receive(const int& error, std::size_t bytes_transferred);

  static void handle_send(
      const char*, /*buffer*/
      const int& /*error*/, std::size_t /*bytes_transferred*/) {}

  // Should be in non swapable memory
  folly::MPMCQueue<iovec_q_item_t*>* free_pool_;
  folly::MPMCQueue<iovec_q_item_t*>* work_pool_;
  uint32_t num_threads_;
  char* recv_buffer_alloc_;
  // raw_packet_q_item_t *raw_packet_q_item_alloc_;
  raw_application* app_;
  std::vector<std::thread> threads_;
  int socket_raw;
  sa_family_t sa_family;
};

#endif /* FILE_RAW_HPP_SEEN */
