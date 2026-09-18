/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_UDP_HPP_SEEN
#define FILE_UDP_HPP_SEEN

#include <arpa/inet.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <stdint.h>
#include <sys/socket.h>

#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <system_error>
#include <atomic>
#include <thread>
#include <utility>
#include <vector>

#include "conversions.hpp"
#include "endpoint.hpp"
#include "itti.hpp"
#include "logger.hpp"
#include "thread_sched.hpp"

using namespace oai::logger;

class udp_application {
 public:
  virtual void handle_receive(
      char* recv_buffer, const std::size_t bytes_transferred,
      const endpoint& r_endpoint);
  virtual void start_receive(
      udp_application* gtp_stack,
      const oai::utils::thread_sched_params& sched_params);
  /** @brief Called before the receive thread waits: send whatever the uplink
   *  shaper is holding whose slot has come, and say in nanoseconds how long
   *  until the next one is due. A negative answer means nothing is waiting and
   *  the thread may block as long as it likes. */
  virtual int64_t on_idle() { return -1; }
};
class udp_server;

class udp_server {
#define UDP_RECV_BUFFER_SIZE 8192
// Datagrams pulled per recvmmsg() / coalesced per sendmmsg(). The syscall is
// amortised over the batch, so the batch wants to be big enough that the
// per-call cost stops mattering; Snabb, which is built around this idea, moves
// ~100 packets per step. Past that the receive buffers stop fitting in L2 and
// latency grows for no more throughput.
#define UDP_RECV_VLEN 64
// Max receive threads, one socket each (see sockets_).
#define UDP_MAX_RX_THREADS 16
// datagrams coalesced into one sendmmsg() on the transmit side
#define UDP_TX_BATCH 64
 public:
  udp_server(const struct in_addr& address, const uint16_t port_num)
      : app_(nullptr), port_(port_num) {
    socket_ = create_socket(address, port_);
    if (socket_ > 0) {
      Logger::udp().debug(
          "udp_server::udp_server(%s:%d)",
          oai::utils::conv::toString(address).c_str(), port_);
      sa_family = AF_INET;
    } else {
      Logger::udp().error(
          "udp_server::udp_server(%s:%d)",
          oai::utils::conv::toString(address).c_str(), port_);
      std::this_thread::sleep_for(std::chrono::milliseconds(500));
      throw std::system_error(
          socket_, std::generic_category(), "GTPV1-U socket creation failed!");
    }
  }

  udp_server(const struct in6_addr& address, const uint16_t port_num)
      : app_(nullptr), port_(port_num) {
    socket_ = create_socket(address, port_);
    if (socket_ > 0) {
      Logger::udp().debug(
          "udp_server::udp_server(%s:%d)",
          oai::utils::conv::toString(address).c_str(), port_);
      sa_family = AF_INET6;
    } else {
      Logger::udp().error(
          "udp_server::udp_server(%s:%d)",
          oai::utils::conv::toString(address).c_str(), port_);
      std::this_thread::sleep_for(std::chrono::milliseconds(500));
      throw std::system_error(
          socket_, std::generic_category(), "GTPV1-U socket creation failed!");
    }
  }

  udp_server(const char* address, const uint16_t port_num)
      : app_(nullptr), port_(port_num) {
    socket_ = create_socket(address, port_);
    if (socket_ > 0) {
      Logger::udp().debug("udp_server::udp_server(%s:%d)", address, port_);
    } else {
      Logger::udp().error("udp_server::udp_server(%s:%d)", address, port_);
      std::this_thread::sleep_for(std::chrono::milliseconds(500));
      throw std::system_error(
          socket_, std::generic_category(), "GTPV1-U socket creation failed!");
    }
  }

  ~udp_server() {
    int res;

    Logger::udp().info("Starting the udp_server destruction");
    stop();

    // Closing a socket is not enough to stop a blocking call; shutdown() is,
    // and it wakes every thread parked in recvmmsg() at once. Every socket in
    // the pool has a thread parked on it, so every one has to be woken.
    shutdown(socket_, SHUT_RDWR);
    for (int sd : sockets_)
      if (sd != socket_) shutdown(sd, SHUT_RDWR);

    // Join before closing: the fd must stay valid until the last thread has
    // left the call that is using it.
    for (auto& t : rthreads_) {
      if (t.joinable()) t.join();
    }
    if (rthread_.joinable()) rthread_.join();

    for (int sd : sockets_)
      if (sd != socket_) close(sd);
    sockets_.clear();

    res = close(socket_);
    if (res != 0) {
      Logger::udp().error("close on socket_ failed %s", strerror(errno));
    }

    Logger::udp().info("Finished the udp_server destruction");
  }

  /** @brief Receive loop for one thread, reading its own socket @p fd. */
  void udp_read_loop(
      oai::utils::thread_sched_params thread_sched_params, int fd);

  /** @brief Start coalescing this thread's sends; flush_tx() issues them.
   *  The buffers handed to async_send_to() must stay valid until the flush.
   *  @param idx caller's queue number, which picks the socket to send on so
   *             that transmitting threads do not share one. */
  void begin_tx_batch(int idx = 0);
  /** @brief Send everything this thread has queued, in one sendmmsg(). */
  void flush_tx_batch();

  void async_send_to(
      const char* send_buffer, const ssize_t num_bytes,
      const endpoint& r_endpoint) {
    ssize_t bytes_written = sendto(
        socket_, send_buffer, num_bytes, 0,
        (struct sockaddr*) &r_endpoint.addr_storage,
        r_endpoint.addr_storage_len);
    if (bytes_written != num_bytes) {
      Logger::udp().error("sendto failed(%d:%s)\n", errno, strerror(errno));
    }
  }

  /// @param tos Transport Level Marking (§8.2.24) for the outer header, 0 for
  /// none. The kernel builds that header, so it travels as a control message
  /// rather than in the buffer. Only the batched path carries it -- that is
  /// the one the downlink datapath uses; nothing else marks.
  void async_send_to(
      const char* send_buffer, const ssize_t num_bytes,
      const struct sockaddr_in& r_endpoint, uint8_t tos = 0) {
    if (tx_batching_) {
      queue_tx(
          send_buffer, num_bytes, &r_endpoint, sizeof(struct sockaddr_in), tos);
      return;
    }
    ssize_t bytes_written = sendto(
        socket_, send_buffer, num_bytes, 0, (struct sockaddr*) &r_endpoint,
        sizeof(struct sockaddr_in));
    if (bytes_written != num_bytes) {
      Logger::udp().error("sendto failed(%d:%s)\n", errno, strerror(errno));
    }
  }

  void async_send_to(
      const char* send_buffer, const ssize_t num_bytes,
      const struct sockaddr_in6& r_endpoint) {
    ssize_t bytes_written = sendto(
        socket_, send_buffer, num_bytes, 0, (struct sockaddr*) &r_endpoint,
        sizeof(struct sockaddr_in6));
    if (bytes_written != num_bytes) {
      Logger::udp().error("sendto failed(%d:%s)\n", errno, strerror(errno));
    }
  }

  void start_receive(
      udp_application* gtp_stack,
      const oai::utils::thread_sched_params& sched_params, int n_rx = 1);

  /** @brief CPU the control plane is pinned to: the *slowest* core of this
   *  process's allowed set, or its lowest-numbered CPU when the cores are all
   *  alike. -1 when there is only one CPU, in which case nothing is pinned.
   *
   *  Datapath threads run at real-time priority, so without a core of its own
   *  the N4 thread stops answering PFCP heartbeats as soon as the datapath
   *  saturates -- and the SMF then removes the association. Which core to give
   *  up matters on a hybrid CPU: the lowest-numbered one is normally a fast
   *  core (Intel P-core, ARM big), and handing that to a control plane that
   *  uses about 2% of it while the datapath runs on the slow cores is
   *  backwards. */
  static int control_cpu();

  /** @brief CPUs to run @p n datapath threads on, drawn from the allowed set
   *  minus control_cpu().
   *
   *  Every call returns the same list, so uplink thread i and downlink thread
   *  i share a core: only one of the pair is on the path for a given
   *  direction. Empty when nothing should be pinned. */
  static std::vector<int> datapath_cpus(int n);
  void stop(void);

 private:
  void queue_tx(
      const char* buf, ssize_t len, const void* addr, socklen_t addrlen,
      uint8_t tos = 0) {
    struct iovec& iov = tx_iov_[tx_count_];
    iov.iov_base      = const_cast<char*>(buf);
    iov.iov_len       = (size_t) len;
    memcpy(&tx_addr_[tx_count_], addr, addrlen);
    struct msghdr& m = tx_msgs_[tx_count_].msg_hdr;
    memset(&tx_msgs_[tx_count_], 0, sizeof(tx_msgs_[tx_count_]));
    m.msg_name    = &tx_addr_[tx_count_];
    m.msg_namelen = addrlen;
    m.msg_iov     = &iov;
    m.msg_iovlen  = 1;
    if (tos) {
      auto* c              = (struct cmsghdr*) tx_cmsg_[tx_count_];
      c->cmsg_level        = IPPROTO_IP;
      c->cmsg_type         = IP_TOS;
      c->cmsg_len          = CMSG_LEN(sizeof(int));
      *(int*) CMSG_DATA(c) = tos;
      m.msg_control        = tx_cmsg_[tx_count_];
      m.msg_controllen     = CMSG_SPACE(sizeof(int));
    }
    if (++tx_count_ >= UDP_TX_BATCH) flush_tx_batch();
  }

 protected:
  int create_socket(const struct in_addr& address, const uint16_t port);
  /// Another socket on the same address/port, joining the SO_REUSEPORT group.
  int clone_socket();
  void apply_socket_options(int sd);
  int create_socket(const struct in6_addr& address, const uint16_t port);
  int create_socket(const char* address, const uint16_t port_num);

  // void handle_receive(const int& error, std::size_t bytes_transferred);

  static void handle_send(
      const char*, /*buffer*/
      const int& /*error*/, std::size_t /*bytes_transferred*/) {}

  udp_application* app_;
  std::vector<std::thread> rthreads_;
  // Transmit batch, per thread. Off unless begin_tx_batch() was called.
  static thread_local bool tx_batching_;
  static thread_local int tx_count_;
  /// Socket this thread transmits on; -1 until begin_tx_batch()/read loop.
  static thread_local int tx_sock_;
  static thread_local struct mmsghdr tx_msgs_[UDP_TX_BATCH];
  static thread_local struct iovec tx_iov_[UDP_TX_BATCH];
  static thread_local struct sockaddr_storage tx_addr_[UDP_TX_BATCH];
  static thread_local char tx_cmsg_[UDP_TX_BATCH][CMSG_SPACE(sizeof(int))];
  std::thread rthread_;
  std::atomic<bool> terminateRL_{false};
  int socket_;
  /// One socket per receive thread; sockets_[0] is socket_. Empty until
  /// start_receive() runs, so anything sending before then uses socket_.
  std::vector<int> sockets_;
  /// The endpoint socket_ is bound to, so clone_socket() can bind more there.
  struct sockaddr_storage bind_addr_ {};
  socklen_t bind_addrlen_{0};
  uint16_t port_;
  sa_family_t sa_family;
};

#endif /* FILE_UDP_HPP_SEEN */
