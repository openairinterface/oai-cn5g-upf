/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "udp.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <vector>

#include "logger.hpp"

using namespace oai::logger;

//------------------------------------------------------------------------------
void udp_application::handle_receive(
    char* recv_buffer, const std::size_t bytes_transferred,
    const endpoint& r_endpoint) {
  Logger::udp().warn("Missing implementation of interface udp_application");
}

//------------------------------------------------------------------------------
void udp_application::start_receive(
    udp_application* gtp_stack,
    const oai::utils::thread_sched_params& sched_params) {
  Logger::udp().warn("Missing implementation of interface udp_application");
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
thread_local bool udp_server::tx_batching_ = false;
thread_local int udp_server::tx_count_     = 0;
thread_local int udp_server::tx_sock_      = -1;
thread_local struct mmsghdr udp_server::tx_msgs_[UDP_TX_BATCH];
thread_local struct iovec udp_server::tx_iov_[UDP_TX_BATCH];
thread_local struct sockaddr_storage udp_server::tx_addr_[UDP_TX_BATCH];
thread_local char udp_server::tx_cmsg_[UDP_TX_BATCH][CMSG_SPACE(sizeof(int))];

//------------------------------------------------------------------------------
void udp_server::begin_tx_batch(int idx) {
  tx_batching_ = true;
  tx_count_    = 0;
  // Send on this thread's own socket. Sharing one socket for transmit puts
  // every downlink thread on the same sk_wmem_alloc, which is an atomic on one
  // cache line that all of them write for every packet. idx is the caller's
  // queue number, so downlink thread i and receive thread i land on the same
  // socket and nothing is shared between threads at all.
  tx_sock_ = sockets_.empty() ? socket_ : sockets_[idx % sockets_.size()];
}

//------------------------------------------------------------------------------
// One sendmmsg() replaces up to UDP_TX_BATCH sendto() calls. The downlink used
// to pay a syscall per packet on transmit; the uplink already batched receive.
void udp_server::flush_tx_batch() {
  if (tx_count_ <= 0) return;
  int n     = tx_count_;
  tx_count_ = 0;  // reset first: a short send must not be retried into itself
  int sent  = sendmmsg(tx_sock_ >= 0 ? tx_sock_ : socket_, tx_msgs_, n, 0);
  if (sent < n) {
    Logger::udp().error(
        "sendmmsg sent %d of %d (%s)", sent, n, strerror(errno));
  }
}

//------------------------------------------------------------------------------
void udp_server::udp_read_loop(
    oai::utils::thread_sched_params sched_params, int fd) {
  sched_params.apply(TASK_NONE, Logger::udp());

  // One recvmmsg() collects up to UDP_RECV_VLEN datagrams per syscall and each
  // is handed to the application on this same thread.  This thread owns `fd`:
  // the sockets share an address through SO_REUSEPORT and the kernel hashes
  // each flow to one of them, so the work spreads without anything having to
  // decide where a packet goes, and no receive queue is touched by two threads.
  // Transmit goes out of the same socket, so a flow uses one socket end to end.
  tx_sock_ = fd;
  std::vector<char> bufs(
      static_cast<size_t>(UDP_RECV_VLEN) * UDP_RECV_BUFFER_SIZE);
  struct mmsghdr msgs[UDP_RECV_VLEN];
  struct iovec iovecs[UDP_RECV_VLEN];
  struct sockaddr_storage addrs[UDP_RECV_VLEN];

  for (int i = 0; i < UDP_RECV_VLEN; i++) {
    iovecs[i].iov_base = &bufs[static_cast<size_t>(i) * UDP_RECV_BUFFER_SIZE];
    iovecs[i].iov_len  = UDP_RECV_BUFFER_SIZE;
  }

  while (1) {
    for (int i = 0; i < UDP_RECV_VLEN; i++) {
      memset(&msgs[i], 0, sizeof(msgs[i]));
      msgs[i].msg_hdr.msg_iov     = &iovecs[i];
      msgs[i].msg_hdr.msg_iovlen  = 1;
      msgs[i].msg_hdr.msg_name    = &addrs[i];
      msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
    }

    int nrecv = recvmmsg(fd, msgs, UDP_RECV_VLEN, MSG_WAITFORONE, nullptr);

    if (terminateRL_) return;
    if (nrecv < 0) {
      if (errno == EINTR) continue;
      Logger::udp().error("recvmmsg failed %s", strerror(errno));
      return;
    }
    for (int i = 0; i < nrecv; i++) {
      endpoint r_endpoint(addrs[i], msgs[i].msg_hdr.msg_namelen);
      app_->handle_receive(
          static_cast<char*>(iovecs[i].iov_base), msgs[i].msg_len, r_endpoint);
    }
  }
}

//------------------------------------------------------------------------------
// clone_socket -- another socket on the very same address and port.
//
// SO_REUSEPORT was already being set on the one socket this class created,
// which did nothing: the kernel only hashes datagrams across a group, and a
// group of one is just a socket. With a socket per receive thread the group is
// real, and each thread then has its own receive queue, its own
// sk_receive_queue lock and its own sk_rmem_alloc counter instead of every
// thread contending for one set shared between them.
int udp_server::clone_socket() {
  if (bind_addrlen_ == 0) return -1;
  int sd = socket(bind_addr_.ss_family, SOCK_DGRAM, IPPROTO_UDP);
  if (sd < 0) {
    Logger::udp().error("pool socket creation failed (%s)", strerror(errno));
    return -1;
  }
  apply_socket_options(sd);  // must set SO_REUSEPORT before bind()
  if (bind(sd, (struct sockaddr*) &bind_addr_, bind_addrlen_) < 0) {
    Logger::udp().error("pool socket bind failed (%s)", strerror(errno));
    close(sd);
    return -1;
  }
  return sd;
}

//------------------------------------------------------------------------------
void udp_server::apply_socket_options(int sd) {
  int on = 1;
  // Every socket in the pool must set SO_REUSEPORT before bind() so the
  // kernel will hash incoming datagrams across them.
  if (setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0) {
    Logger::udp().error(
        "Socket option reuse port failed (%s)", strerror(errno));
  }
  int bufsz = 16 * 1024 * 1024;
  if (setsockopt(sd, SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(bufsz)) < 0) {
    Logger::udp().warn("Socket option SO_RCVBUF failed (%s)", strerror(errno));
  }
  if (setsockopt(sd, SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz)) < 0) {
    Logger::udp().warn("Socket option SO_SNDBUF failed (%s)", strerror(errno));
  }
}

//------------------------------------------------------------------------------
int udp_server::create_socket(
    const struct in_addr& address, const uint16_t port) {
  struct sockaddr_in addr = {};
  int sd                  = 0;

  /*
   * Create UDP socket
   */
  if ((sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    /*
     * Socket creation has failed...
     */
    Logger::udp().error("Socket creation failed (%s)", strerror(errno));
    return errno;
  }

  apply_socket_options(sd);

  addr.sin_family      = AF_INET;
  addr.sin_port        = htons(port);
  addr.sin_addr.s_addr = address.s_addr;

  socklen_t unused_bind_len_ = sizeof(addr);

  std::string ipv4 = oai::utils::conv::toString(address);
  Logger::udp().debug(
      "Creating new listen socket on address %s and port %" PRIu16 "\n",
      ipv4.c_str(), port);

  if (bind(sd, (struct sockaddr*) &addr, sizeof(struct sockaddr_in)) < 0) {
    /*
     * Bind failed
     */
    Logger::udp().error(
        "Socket bind failed (%s) for address %s and port %" PRIu16 "\n",
        strerror(errno), ipv4.c_str(), port);
    close(sd);
    return errno;
  }
  sa_family = AF_INET;
  // Remembered so clone_socket() can bind more sockets to this same address:
  // SO_REUSEPORT only spreads traffic when several sockets share one endpoint.
  memcpy(&bind_addr_, &addr, sizeof(addr));
  bind_addrlen_ = sizeof(addr);
  return sd;
}
//------------------------------------------------------------------------------
int udp_server::create_socket(
    const struct in6_addr& address, const uint16_t port) {
  struct sockaddr_in6 addr = {};
  int sd                   = 0;

  /*
   * Create UDP socket
   */
  if ((sd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    /*
     * Socket creation has failed...
     */
    Logger::udp().error("Socket creation failed (%s)", strerror(errno));
    return errno;
  }

  addr.sin6_family = AF_INET6;
  addr.sin6_port   = htons(port);
  addr.sin6_addr   = address;

  apply_socket_options(sd);
  socklen_t unused_bind_len_ = sizeof(addr);

  std::string ipv6 = oai::utils::conv::toString(address);
  Logger::udp().debug(
      "Creating new listen socket on address %s and port %" PRIu16 "\n",
      ipv6.c_str(), port);

  if (bind(sd, (struct sockaddr*) &addr, sizeof(struct sockaddr_in6)) < 0) {
    /*
     * Bind failed
     */
    Logger::udp().error(
        "Socket bind failed (%s) for address %s and port %" PRIu16 "\n",
        strerror(errno), ipv6.c_str(), port);
    close(sd);
    return errno;
  }
  sa_family = AF_INET6;
  memcpy(&bind_addr_, &addr, sizeof(addr));
  bind_addrlen_ = sizeof(addr);
  return sd;
}
//------------------------------------------------------------------------------
int udp_server::create_socket(const char* address, const uint16_t port_num) {
  unsigned char buf_in_addr[sizeof(struct in6_addr)];
  if (inet_pton(AF_INET, address, buf_in_addr) == 1) {
    struct in_addr addr4 = {};
    memcpy(&addr4, buf_in_addr, sizeof(struct in_addr));
    return create_socket(addr4, port_num);
  } else if (inet_pton(AF_INET6, address, buf_in_addr) == 1) {
    struct in6_addr addr6 = {};
    memcpy(&addr6, buf_in_addr, sizeof(struct in6_addr));
    return create_socket(addr6, port_num);
  } else {
    Logger::udp().error("udp_server::create_socket(%s:%d)", address, port_num);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    throw std::system_error(
        socket_, std::generic_category(), "UDP socket creation failed!");
  }
}
//------------------------------------------------------------------------------
// cpu_max_khz -- the kernel's view of how fast a core is, 0 when it does not
// say. On Intel hybrid parts P-cores and E-cores report different values
// (5000000 vs 3700000 on an i7-1355U); on ARM big.LITTLE likewise. Uniform
// machines report one value for every core, and the caller falls back to
// picking the lowest-numbered CPU.
//------------------------------------------------------------------------------
static long cpu_max_khz(int cpu) {
  char path[80];
  snprintf(
      path, sizeof(path),
      "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_max_freq", cpu);
  FILE* f = fopen(path, "re");
  if (!f) return 0;
  long khz = 0;
  if (fscanf(f, "%ld", &khz) != 1) khz = 0;
  fclose(f);
  return khz;
}

//------------------------------------------------------------------------------
// A hybrid split is large -- Intel P vs E is about 26% (5.0 vs 3.7 GHz), ARM
// big.LITTLE more. Per-core binning differences on a uniform machine are about
// 1% (a GH200 reports 3384-3420 MHz across its cores). Anything under this
// threshold is noise and must not decide which core to give up, or the choice
// becomes arbitrary and changes between otherwise identical hosts.
#define CPU_SLOW_TIER_NUM 85
#define CPU_SLOW_TIER_DEN 100

//------------------------------------------------------------------------------
int udp_server::control_cpu() {
  cpu_set_t allowed;
  CPU_ZERO(&allowed);
  if (sched_getaffinity(0, sizeof(allowed), &allowed) != 0) return -1;
  if (CPU_COUNT(&allowed) < 2) return -1;  // nothing to spare

  int lowest   = -1;
  long fastest = 0;
  for (int c = 0; c < CPU_SETSIZE; c++) {
    if (!CPU_ISSET(c, &allowed)) continue;
    if (lowest < 0) lowest = c;
    const long khz = cpu_max_khz(c);
    if (khz > fastest) fastest = khz;
  }
  if (fastest == 0) return lowest;  // kernel does not report speeds

  // Lowest-numbered core of the slow tier, so the answer is deterministic;
  // when there is no slow tier every core is equivalent and the lowest wins.
  const long tier = fastest * CPU_SLOW_TIER_NUM / CPU_SLOW_TIER_DEN;
  for (int c = 0; c < CPU_SETSIZE; c++) {
    if (!CPU_ISSET(c, &allowed)) continue;
    const long khz = cpu_max_khz(c);
    if (khz > 0 && khz < tier) return c;
  }
  return lowest;
}

//------------------------------------------------------------------------------
std::vector<int> udp_server::datapath_cpus(int n) {
  // Both pools get the same list, so uplink thread i and downlink thread i
  // share a core on purpose. A packet is carried end to end by one thread of
  // one pool -- the tun thread encapsulates and transmits its own downlink,
  // the N3 thread decapsulates and writes its own uplink -- so for a given
  // direction only one of the pair is on the path at all. Measured: a downlink
  // run with the pools on separate cores left every N3 core at 0% while the
  // tun cores saturated. Sharing therefore costs nothing a unidirectional load
  // can see, and asks for max(n3_rx_threads, dl_rx_queues) + 1 CPUs instead of
  // the sum. A full-duplex load does put both on one core; give it more CPUs.
  static std::mutex mu;
  static std::vector<int> pool;
  static bool warned = false;
  std::lock_guard<std::mutex> lk(mu);

  if (pool.empty()) {
    cpu_set_t allowed;
    CPU_ZERO(&allowed);
    if (sched_getaffinity(0, sizeof(allowed), &allowed) != 0) return {};
    if (CPU_COUNT(&allowed) < 2) return {};  // leave everything unpinned
    const int control = control_cpu();
    for (int c = 0; c < CPU_SETSIZE; c++)
      if (CPU_ISSET(c, &allowed) && c != control) pool.push_back(c);
    if (pool.empty()) return {};
  }

  std::vector<int> out;
  for (int i = 0; i < n; i++) out.push_back(pool[(size_t) i % pool.size()]);

  // More threads in one pool than there are cores: now two threads of the same
  // direction share, which is the sharing that does cost throughput.
  if (!warned && (size_t) n > pool.size()) {
    warned = true;
    Logger::udp().warn(
        "%d datapath thread(s) of one direction on %zu CPU(s) after reserving "
        "one for the control plane, so they share cores. Give the container "
        "max(n3_rx_threads, dl_rx_queues) + 1 CPUs",
        n, pool.size());
  }
  return out;
}

//------------------------------------------------------------------------------
void udp_server::start_receive(
    udp_application* app, const oai::utils::thread_sched_params& sched_params,
    int n_rx) {
  app_ = app;
  Logger::udp().trace("udp_server::start_receive");

  if (n_rx < 1) n_rx = 1;
  if (n_rx > UDP_MAX_RX_THREADS) n_rx = UDP_MAX_RX_THREADS;

  // One socket per receive thread. The first is the one the constructor made,
  // so the control path keeps working through socket_ unchanged; the rest join
  // its SO_REUSEPORT group. A socket that no thread reads would still be given
  // datagrams by the hash and silently fill, so the pool is exactly as large
  // as the number of readers -- never larger.
  sockets_.clear();
  sockets_.push_back(socket_);
  for (int i = 1; i < n_rx; i++) {
    const int sd = clone_socket();
    if (sd < 0) {
      Logger::udp().warn(
          "port %d: only %zu of %d sockets; the rest share, which is slower "
          "but correct",
          port_, sockets_.size(), n_rx);
      break;
    }
    sockets_.push_back(sd);
  }

  const std::vector<int> cpus =
      n_rx > 1 ? datapath_cpus(n_rx) : std::vector<int>{};
  std::string where;
  for (int c : cpus)
    where.append(where.empty() ? " on CPU " : ",").append(std::to_string(c));
  Logger::udp().info(
      "udp_server on port %d: %d receive thread(s), %zu socket(s)%s", port_,
      n_rx, sockets_.size(), where.c_str());

  for (int i = 0; i < n_rx; i++) {
    oai::utils::thread_sched_params sp = sched_params;
    if (!cpus.empty()) sp.cpu_id = cpus[i];
    rthreads_.emplace_back(
        &udp_server::udp_read_loop, this, sp, sockets_[i % sockets_.size()]);
  }
}

//------------------------------------------------------------------------------
void udp_server::stop(void) {
  terminateRL_ = true;
}
