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
 public:
  raw_server(const char* ifname)
      : app_(nullptr),
        free_pool_(nullptr),
        work_pool_(nullptr) {
    socket_ = create_socket(ifname);
    if (socket_ > 0) {
      Logger::raw().debug("raw_server::raw_server(%s)", ifname);
    } else {
      Logger::raw().error("raw_server::raw_server(%s)", ifname);
      std::this_thread::sleep_for(std::chrono::milliseconds(500));
      throw std::system_error(
          socket_, std::generic_category(), "GTPV1-U socket creation failed!");
    }
  }

  ~raw_server() {
    close(socket_);
    // TODO delete/release elements in  the pool
    delete free_pool_;
    delete work_pool_;
    free(recv_buffer_alloc_);
    // free(raw_packet_q_item_alloc_);
  }

  void raw_read_loop(const util::thread_sched_params& thread_sched_params);
  void raw_worker_loop(
      const int id, const util::thread_sched_params& sched_params);

  void async_send_to(
      const char* send_buffer, const ssize_t num_bytes,
      const endpoint& r_endpoint) {
    ssize_t bytes_written = sendto(
        socket_, send_buffer, num_bytes, 0,
        (struct sockaddr*) &r_endpoint.addr_storage,
        r_endpoint.addr_storage_len);
    if (bytes_written != num_bytes) {
      Logger::raw().error("sendto failed(%d:%s)\n", errno, strerror(errno));
    }
  }

  void async_send_to(
      const char* send_buffer, const ssize_t num_bytes,
      const struct sockaddr_in& r_endpoint) {
    ssize_t bytes_written = sendto(
        socket_, send_buffer, num_bytes, 0, (struct sockaddr*) &r_endpoint,
        sizeof(struct sockaddr_in));
    if (bytes_written != num_bytes) {
      Logger::raw().error("sendto failed(%d:%s)\n", errno, strerror(errno));
    }
  }

  void async_send_to(
      const char* send_buffer, const ssize_t num_bytes,
      const struct sockaddr_in6& r_endpoint) {
    ssize_t bytes_written = sendto(
        socket_, send_buffer, num_bytes, 0, (struct sockaddr*) &r_endpoint,
        sizeof(struct sockaddr_in6));
    if (bytes_written != num_bytes) {
      Logger::raw().error("sendto failed(%d:%s)\n", errno, strerror(errno));
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
  int socket_;
  sa_family_t sa_family;
};

#endif /* FILE_RAW_HPP_SEEN */
