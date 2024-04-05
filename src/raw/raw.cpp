#include "raw.hpp"

#include <cstdlib>
#include <linux/if.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <sys/ioctl.h>

//------------------------------------------------------------------------------
void raw_application::handle_receive(
    const char* recv_buffer, const std::size_t bytes_transferred) {
  Logger::raw().warn("Missing implementation of interface raw_application\n");
}

//------------------------------------------------------------------------------
void raw_application::start_receive(
    raw_application* gtp_stack, const util::thread_sched_params& sched_params) {
  Logger::raw().warn("Missing implementation of interface raw_application\n");
}

//------------------------------------------------------------------------------
static std::string string_to_hex(const std::string& input) {
  static const char* const lut = "0123456789ABCDEF";
  size_t len                   = input.length();

  std::string output;
  output.reserve(2 * len);
  for (size_t i = 0; i < len; ++i) {
    const unsigned char c = input[i];
    output.push_back(lut[c >> 4]);
    output.push_back(lut[c & 15]);
  }
  return output;
}
//------------------------------------------------------------------------------
void raw_server::raw_worker_loop(
    const int id, const util::thread_sched_params& sched_params) {
  uint64_t count              = 0;
  iovec_q_item_t* iov = nullptr;

  sched_params.apply(TASK_NONE, Logger::udp());
  while (1) {
    work_pool_->blockingRead(iov);
    ++count;
    // std::cout << "DL worker " << id << " count " << count << std::endl;
    // exit thread
    if (iov->msg_iov.iov_base) {
      app_->handle_receive((const char*) iov->msg_iov.iov_base, iov->msg_iov.iov_len);
      free_pool_->blockingWrite(iov);
    } else {
      free(iov);
      std::cout << "exit DL w" << id << " " << count << std::endl;
      while (work_pool_->readIfNotEmpty(iov)) {
        free(iov);
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
      }
      return;
    }
    iov = nullptr;
  }
}

//------------------------------------------------------------------------------
void raw_server::raw_read_loop(const util::thread_sched_params& sched_params) {
  uint64_t count              = 0;
  uint64_t errors     = 0;
  iovec_q_item_t* iov = nullptr;
  // raw_packet_q_item_t* worker = nullptr;

  // Producer should not interfere with consumer for not de-sequence IP packets
  // sched_params.sched_priority -= 1;
  sched_params.apply(TASK_NONE, Logger::raw());

  while (1) {
    if (!iov) {
      free_pool_->blockingRead(iov);
    }

    iov->msg_iov.iov_len = RAW_RECV_BUFFER_SIZE - ROOM_FOR_ENCAP;

    if (iov->msg_iov.iov_base == nullptr) {
      free(iov);
      while (work_pool_->readIfNotEmpty(iov)) {
        free(iov);
      }
      std::cout << "exit d" << count << std::endl;
      return;
    }
    ssize_t nread;
    if ((nread = read(socket_raw, iov->msg_iov.iov_base, iov->msg_iov.iov_len)) >
        0) {
      ++count;
      // std::cout << "pdn" << count << " " << nread << " bytes" << std::endl;
      iov->msg_iov.iov_len = nread;
      work_pool_->blockingWrite(iov);
      iov = nullptr;
    } else {
      ++errors;
      Logger::raw().error(
          "recvmsg failed rc=%d:%s nb_errors %d", nread, strerror(errno),
          errors);
      std::this_thread::sleep_for(std::chrono::milliseconds(1000));
      exit(0);
    }
  }
}

//------------------------------------------------------------------------------
int raw_server::create_socket(const char* ifname) {
  unsigned char buf_in_addr[sizeof(struct in6_addr)];
  int sd                   = 0;
  bool promisc = true;
  /*
   * Create socket
   * The  socket_type is either SOCK_RAW for raw packets including the
   * link-level header or SOCK_DGRAM for cooked packets with the link-level
   * header removed.
   */

  if ((sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    /*
     * Socket creation has failed...
     */
    Logger::raw().error("Socket creation failed (%s)", strerror(errno));
    return -1;
  }

  struct ifreq ifr = {};
  strncpy((char*) ifr.ifr_name, ifname, IFNAMSIZ);
  if (ioctl(sd, SIOCGIFINDEX, &ifr) < 0) {
    Logger::raw().error(
        "Get interface index failed (%s) for %s", strerror(errno), ifname);
    close(sd);
    return -1;
  }

  int if_index = ifr.ifr_ifindex;

  struct sockaddr_ll sll = {};
  sll.sll_family         = AF_PACKET;        /* Always AF_PACKET */
  sll.sll_protocol       = htons(ETH_P_ALL); /* Physical-layer protocol */
  sll.sll_ifindex        = ifr.ifr_ifindex;  /* Interface number */
  sll.sll_pkttype        = PACKET_HOST;
  if (bind(sd, (struct sockaddr*) &sll, sizeof(sll)) < 0) {
    /*
      * Bind failed
      */
    Logger::raw().error(
        "Socket bind to %s failed (%s)", ifname, strerror(errno));
    close(sd);
    return -1;
  }

  if (promisc) {
    struct packet_mreq mreq = {};
    mreq.mr_ifindex         = if_index;
    mreq.mr_type            = PACKET_MR_PROMISC;
    if (setsockopt(
            sd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
      Logger::raw().error(
          "Set promiscuous mode failed (%s)", strerror(errno));
      close(sd);
      return -1;
    }
  }
  return sd;
}

//------------------------------------------------------------------------------
void raw_server::start_receive(
    raw_application* app, const util::thread_sched_params& sched_params) {
  num_threads_   = sched_params.thread_pool_size;
  int num_blocks = num_threads_ * 16;
  app_           = app;
  Logger::raw().debug("raw_server::start_receive");
 
  free_pool_     = new folly::MPMCQueue<iovec_q_item_t*>(num_blocks);
  work_pool_     = new folly::MPMCQueue<iovec_q_item_t*>(num_blocks);

  recv_buffer_alloc_ = (char*) calloc(num_blocks, RAW_RECV_BUFFER_SIZE );

  for (int i = 0; i < num_blocks; i++) {
    iovec_q_item_s* v = (iovec_q_item_s*) calloc(1, sizeof(iovec_q_item_s));
    v->msg_iov.iov_base =
        (void*) ((uintptr_t) calloc(1, RAW_RECV_BUFFER_SIZE ) + (uintptr_t) ROOM_FOR_ENCAP);
    v->msg_iov.iov_len = RAW_RECV_BUFFER_SIZE - ROOM_FOR_ENCAP;
    v->msg.msg_iovlen  = 1;
    v->msg.msg_flags   = 0;
    v->msg.msg_control = nullptr;
    v->msg.msg_controllen = 0;
    free_pool_->blockingWrite(v);
  }
  for (int i = 0; i < num_threads_; i++) {
    std::thread t =
        std::thread(&raw_server::raw_worker_loop, this, i, sched_params);
    threads_.push_back(std::move(t));
  }
  std::thread t = std::thread(&raw_server::raw_read_loop, this, sched_params);
  t.detach();
  threads_.push_back(std::move(t));
}
//------------------------------------------------------------------------------
void raw_server::stop(void) {
  for (int i = 0; i < num_threads_; i++) {
    iovec_q_item_t* p =
        (iovec_q_item_t*) calloc(1, sizeof(iovec_q_item_t));
    work_pool_->blockingWrite(p);
  }
  iovec_q_item_t* p =
      (iovec_q_item_t*) calloc(1, sizeof(iovec_q_item_t));
  free_pool_->blockingWrite(p);
  Logger::raw().debug("raw_server::stopped");
}
