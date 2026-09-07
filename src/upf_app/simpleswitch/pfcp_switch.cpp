/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "pfcp_switch.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <stdexcept>
#include <vector>
#include <fcntl.h>
#include <poll.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "common_defs.h"
#include "itti.hpp"
#include "logger.hpp"
#include "qos_mbr.hpp"
#include "simple_switch.hpp"
#include "upf_config.hpp"
#include "upf_n4.hpp"
#include "upf_pfcp_association.hpp"

std::shared_ptr<SessionManager> session_manager;

using namespace pfcp;
using namespace gtpv1u;
using namespace oai::config;
using namespace oai::upf::app;
using namespace std;

extern itti_mw* itti_inst;
extern upf_config upf_cfg;
extern upf_n3* upf_n3_inst;
extern upf_n4* upf_n4_inst;  // Usage Reports are sent over N4
extern pfcp_switch* pfcp_switch_inst;

// =============================================================================
// PDN I/O thread
// =============================================================================

//------------------------------------------------------------------------------
// pdn_read_loop — DL datapath thread.
// Reads IP packets from tun0 and forwards each one inline: PDR look-up, FAR,
// GTP-U encapsulation and send.  One thread, no queue.

//------------------------------------------------------------------------------
void pfcp_switch::pdn_read_loop(
    int sock_r, int idx, oai::utils::thread_sched_params sched_params) {
  uint64_t errors = 0;

  if (idx == 0) prThreadToCancel = pthread_self();
  sched_params.apply(TASK_NONE, Logger::pfcp_switch());

  // This thread owns tun queue `idx` and is the only reader of it. The kernel
  // steers a flow to one queue and keeps it there, so every packet of a flow
  // is handled by this one thread and cannot overtake itself. Several threads
  // sharing one queue -- what this replaced -- reordered ~17% of packets.
  //
  // The buffers keep ROOM_FOR_GTPV1U_G_PDU of headroom in front so that
  // send_g_pdu() can write the GTP-U header in place without a copy. A tun fd
  // yields one packet per read() and cannot be batched on receive; the
  // transmit side is batched instead -- drain up to DL_BATCH packets,
  // encapsulate them all, then hand the lot to one sendmmsg().
  constexpr int DL_BATCH = UDP_TX_BATCH;
  const size_t payload_capacity =
      PFCP_SWITCH_RECV_BUFFER_SIZE - ROOM_FOR_GTPV1U_G_PDU;
  std::vector<char> bufs((size_t) DL_BATCH * PFCP_SWITCH_RECV_BUFFER_SIZE);
  char* payload[DL_BATCH];
  ssize_t len[DL_BATCH];
  for (int i = 0; i < DL_BATCH; i++)
    payload[i] = bufs.data() + (size_t) i * PFCP_SWITCH_RECV_BUFFER_SIZE +
                 ROOM_FOR_GTPV1U_G_PDU;

  // The fd is O_NONBLOCK, so the drain below costs one read() per packet and
  // nothing else. It used to poll() before every read to decide whether more
  // was queued -- two syscalls per packet instead of one -- because the fd had
  // to stay blocking for send_to_core()'s writes. Those now retry on EAGAIN
  // instead, which costs nothing until the queue is actually full.
  struct pollfd pfd = {};
  pfd.fd            = sock_r;
  pfd.events        = POLLIN;

  const int q   = idx < TUN_MAX_QUEUES ? idx : TUN_MAX_QUEUES - 1;
  auto last_log = std::chrono::steady_clock::now();
  if (upf_n3_inst) upf_n3_inst->begin_tx_batch();

  while (1) {
    // One clock read per batch, on one thread only. It has to be here rather
    // than after the batch: this thread only sees a flow the hash sent to its
    // queue, so it can sit in poll() indefinitely while the others are busy --
    // which is exactly when the balance is worth logging.
    if (q == 0) {
      const auto now = std::chrono::steady_clock::now();
      if (now - last_log >= std::chrono::seconds(10)) {
        last_log = now;
        log_tun_queue_balance();
      }
    }

    int n = 0;
    while (n < DL_BATCH) {
      ssize_t r = read(sock_r, payload[n], payload_capacity);
      if (r > 0) {
        len[n++] = r;
        continue;
      }
      if (r < 0 && errno == EINTR) continue;
      if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
      ++errors;
      Logger::pfcp_switch().error(
          "read failed rc=%d:%s nb_errors %d", r, strerror(errno), errors);
      std::this_thread::sleep_for(std::chrono::milliseconds(1000));
      exit(0);
    }

    if (n == 0) {
      // Nothing queued. Anything already encapsulated has been flushed by the
      // previous iteration, so it is safe to sleep here. The timeout only
      // exists so an idle queue-0 thread still reaches the logging above.
      poll(&pfd, 1, q == 0 ? 1000 : -1);
      continue;
    }

    tun_q_[q].rx.fetch_add((uint64_t) n, std::memory_order_relaxed);
    for (int i = 0; i < n; i++)
      pfcp_session_look_up_pack_in_core(payload[i], len[i]);
    if (upf_n3_inst) upf_n3_inst->flush_tx_batch();
  }
}

//------------------------------------------------------------------------------
// log_tun_queue_balance -- one line every LOG_PERIOD, from the first DL thread
// only. The flow hash spreads flows, not packets, so a handful of test flows
// can land unevenly; without this the symptom (one thread at 100%, the rest
// idle) is indistinguishable from a genuine ceiling.
//------------------------------------------------------------------------------
void pfcp_switch::log_tun_queue_balance() {
  if (tun_fds_.size() < 2) return;
  std::string s;
  for (size_t i = 0; i < tun_fds_.size() && i < TUN_MAX_QUEUES; i++)
    s.append(fmt::format(
        "{}q{}: rx {} tx {}", i ? ", " : "", i,
        tun_q_[i].rx.load(std::memory_order_relaxed),
        tun_q_[i].tx.load(std::memory_order_relaxed)));
  Logger::pfcp_switch().debug("tun queue balance -- %s", s.c_str());
}

//------------------------------------------------------------------------------
// flow_hash -- stable hash of an IPv4 flow, symmetric in the two endpoints so
// both directions of a connection land on the same queue.
//------------------------------------------------------------------------------
static inline uint32_t flow_hash(const struct iphdr* iph, std::size_t len) {
  uint32_t h       = iph->saddr ^ iph->daddr;  // symmetric in addresses
  const size_t ihl = (size_t) iph->ihl * 4;
  uint16_t sport = 0, dport = 0;
  if ((iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) &&
      len >= ihl + 4) {
    memcpy(&sport, (const uint8_t*) iph + ihl, sizeof(sport));
    memcpy(&dport, (const uint8_t*) iph + ihl + 2, sizeof(dport));
  }
  h ^= (uint32_t) (uint16_t) (sport ^ dport) << 16;  // symmetric in ports
  h ^= (uint32_t) iph->protocol;
  // Finaliser: the inputs are low-entropy (one subnet, sequential UE
  // addresses), so without mixing the low bits the modulo below would leave
  // whole queues empty.
  h ^= h >> 16;
  h *= 0x7feb352dU;
  h ^= h >> 15;
  h *= 0x846ca68bU;
  h ^= h >> 16;
  return h;
}

//------------------------------------------------------------------------------
int pfcp_switch::tun_tx_fd(const struct iphdr* iph, std::size_t len) const {
  const size_t n = tun_fds_.size();
  if (n == 0) return sock_w;
  if (n == 1) return tun_fds_[0];
  return tun_fds_[flow_hash(iph, len) % n];
}

//------------------------------------------------------------------------------
void pfcp_switch::send_to_core(char* const ip_packet, const ssize_t len) {
  const struct iphdr* iph = (const struct iphdr*) ip_packet;
  const int fd            = tun_tx_fd(iph, (std::size_t) len);
  for (size_t i = 0; i < tun_fds_.size() && i < TUN_MAX_QUEUES; i++)
    if (tun_fds_[i] == fd) {
      tun_q_[i].tx.fetch_add(1, std::memory_order_relaxed);
      break;
    }

  // The fd is non-blocking so the downlink reader does not need a poll() per
  // packet. EAGAIN here means the queue is momentarily full, not that the
  // packet should be dropped -- wait briefly rather than lose it.
  for (int attempt = 0;; attempt++) {
    const ssize_t w = write(fd, ip_packet, len);
    if (w >= 0) return;
    if (errno == EINTR) continue;
    if ((errno == EAGAIN || errno == EWOULDBLOCK) && attempt < 8) {
      struct pollfd p = {fd, POLLOUT, 0};
      poll(&p, 1, 1);
      continue;
    }
    Logger::pfcp_switch().error(
        "write fd %d failed rc=%d:%s", fd, w, strerror(errno));
    return;
  }
}

// =============================================================================
// PDN socket / tun helpers
// =============================================================================

//------------------------------------------------------------------------------
int pfcp_switch::create_pdn_socket(
    const char* const ifname, const bool promisc, int& if_index) {
  struct sockaddr_in addr = {};
  int sd                  = 0;

  /*
   * Create socket
   * The  socket_type is either SOCK_RAW for raw packets including the
   * link-level header or SOCK_DGRAM for cooked packets with the link-level
   * header removed.
   */

  if ((sd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL))) < 0) {
    /*
     * Socket creation has failed...
     */
    Logger::pfcp_switch().error("Socket creation failed (%s)", strerror(errno));
    return RETURNerror;
  }

  if (ifname) {
    struct ifreq ifr = {};
    strncpy((char*) ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(sd, SIOCGIFINDEX, &ifr) < 0) {
      Logger::pfcp_switch().error(
          "Get interface index failed (%s) for %s", strerror(errno), ifname);
      close(sd);
      return RETURNerror;
    }

    if_index = ifr.ifr_ifindex;

    struct sockaddr_ll sll = {};
    sll.sll_family         = AF_PACKET;        /* Always AF_PACKET */
    sll.sll_protocol       = htons(ETH_P_ALL); /* Physical-layer protocol */
    sll.sll_ifindex        = ifr.ifr_ifindex;  /* Interface number */
    sll.sll_pkttype        = PACKET_HOST;
    if (bind(sd, (struct sockaddr*) &sll, sizeof(sll)) < 0) {
      /*
       * Bind failed
       */
      Logger::pfcp_switch().error(
          "Socket bind to %s failed (%s)", ifname, strerror(errno));
      close(sd);
      return RETURNerror;
    }

    if (promisc) {
      struct packet_mreq mreq = {};
      mreq.mr_ifindex         = if_index;
      mreq.mr_type            = PACKET_MR_PROMISC;
      if (setsockopt(
              sd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        Logger::pfcp_switch().error(
            "Set promiscuous mode failed (%s)", strerror(errno));
        close(sd);
        return RETURNerror;
      }
    }
  }
  return sd;
}

//------------------------------------------------------------------------------
int pfcp_switch::create_pdn_socket(const char* const ifname) {
  struct sockaddr_in addr = {};
  int sd                  = RETURNerror;

  if (ifname) {
    /*
     * Create socket
     * The  socket_type is either SOCK_RAW for raw packets including the
     * link-level header or SOCK_DGRAM for cooked packets with the link-level
     * header removed.
     */
    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
      /*
       * Socket creation has failed...
       */
      Logger::pfcp_switch().error(
          "Socket creation failed (%s)", strerror(errno));
      return RETURNerror;
    }

    int option_on          = 1;
    const int* p_option_on = &option_on;
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, p_option_on, sizeof(option_on)) <
        0) {
      Logger::pfcp_switch().error(
          "Set header included failed (%s)", strerror(errno));
      close(sd);
      return RETURNerror;
    }

    struct ifreq ifr = {};
    strncpy((char*) ifr.ifr_name, ifname, IFNAMSIZ);
    if ((setsockopt(
            sd, SOL_SOCKET, SO_BINDTODEVICE, (void*) &ifr, sizeof(ifr))) < 0) {
      Logger::pfcp_switch().error(
          "Socket bind to %s failed (%s)", ifname, strerror(errno));
      close(sd);
      return RETURNerror;
    }
    return sd;
  }
  return RETURNerror;
}

//------------------------------------------------------------------------------
int pfcp_switch::tun_open(char* devname, int flags, bool multi_queue) {
  struct ifreq ifr;
  int fd, err;
  if ((fd = open("/dev/net/tun", flags)) == -1) {
    Logger::pfcp_switch().error("open /dev/net/tun");
    return RETURNerror;
  }
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  // Each open with IFF_MULTI_QUEUE attaches another queue to the same device.
  // The device itself must have been created with multi_queue or this fails.
  if (multi_queue) ifr.ifr_flags |= IFF_MULTI_QUEUE;
  strncpy(ifr.ifr_name, devname, IFNAMSIZ);  // devname = tunX

  if ((err = ioctl(fd, TUNSETIFF, (void*) &ifr)) == -1) {
    Logger::pfcp_switch().error("ioctl TUNSETIFF %d %s", err, strerror(errno));
    close(fd);
    return RETURNerror;
  }
  return fd;
}

//------------------------------------------------------------------------------
void pfcp_switch::setup_pdn_interfaces() {
  std::string cmd = {};
  int rc          = 0;
  // Needed before the device exists: multi_queue can only be asked for at
  // creation time, so the thread count has to be known here.
  int nt = upf_cfg.dl_rx_queues < 1 ? 1 : upf_cfg.dl_rx_queues;
  if (nt > TUN_MAX_QUEUES) nt = TUN_MAX_QUEUES;
  int if_index = 0;

  for (int index = 0; index < upf_cfg.pdns.size(); index++) {
    pdn_cfg_t it = upf_cfg.pdns[index];
    int sock_r   = 0;
    if (index == 0) {
      cmd = fmt::format(
          "ip tuntap add mode tun {}dev tun{}", nt > 1 ? "multi_queue " : "",
          index);
      rc = system((const char*) cmd.c_str());

      cmd = fmt::format("ip link set dev tun{} up", index);
      rc  = system((const char*) cmd.c_str());

      cmd = fmt::format("ethtool -K tun{0} tx-checksum-ip-generic off;", index);
      rc  = system((const char*) cmd.c_str());
    }
    if (it.prefix_ipv4) {
      struct in_addr address4 = {};
      address4.s_addr         = it.network_ipv4.s_addr + be32toh(1);

      if (index == 0) {
        cmd = fmt::format(
            "ip addr add {}/{} dev tun{}",
            oai::utils::conv::toString(address4).c_str(), it.prefix_ipv4,
            index);
        rc = system((const char*) cmd.c_str());
      } else {
        // Remove defult route
        // cmd = fmt::format(
        //     "ip route del {}/{}",
        //     oai::utils::conv::toString(it.network_ipv4).c_str(),
        //     it.prefix_ipv4);
        // rc = system((const char*) cmd.c_str());

        // Add first pdn as gateway for additional PDNs
        struct in_addr address4_gw = {};
        address4_gw.s_addr = upf_cfg.pdns[0].network_ipv4.s_addr + be32toh(1);

        auto routing_info = fr::RoutingInformation{
            oai::utils::conv::toString(it.network_ipv4),
            static_cast<uint32_t>(it.prefix_ipv4), "tun0",
            oai::utils::conv::toString(address4_gw)};
        local_routing->add_route(routing_info);
      }

      if (upf_cfg.enable_snat) {
        auto snat_info = fr::SourceNatInformation{
            oai::utils::conv::toString(it.network_ipv4),
            static_cast<uint32_t>(it.prefix_ipv4), upf_cfg.n6.if_name,
            oai::utils::conv::toString(upf_cfg.n6.addr4)};
        local_routing->add_source_snat(snat_info);
      }
    }
    if (it.prefix_ipv6) {
      std::string cmd = fmt::format(
          "echo 0 > /proc/sys/net/ipv6/conf/tun{}/disable_ipv6", index);
      rc = system((const char*) cmd.c_str());

      struct in6_addr addr6 = it.network_ipv6;
      addr6.s6_addr[15]     = 1;
      cmd                   = fmt::format(
          "ip -6 addr add {}/{} dev tun{}",
          oai::utils::conv::toString(addr6).c_str(), it.prefix_ipv6, index);
      rc = system((const char*) cmd.c_str());
      // if ((it.enable_snat) && (/* SGI has IPv6 address*/)) {
      //   cmd = fmt::format(
      //       "ip6tables -t nat -A POSTROUTING -s {}/{} -o {} -j
      //       SNAT-- to -
      //       source {} ", oai::utils::conv::toString(addr6).c_str(),
      //       it.prefix_ipv6, xxx);
      //   rc = system((const char*) cmd.c_str());
      // }
    }
    // even if we do nat, we can receive ue ip destinated IP packet
    // but do not forget to set routes outside UPF
    // cmd = fmt::format(
    //    "/sbin/sysctl -w net.ipv4.conf.{}.rp_filter=0",
    //    upf_cfg.n6.if_name.c_str());
    // rc = system((const char*) cmd.c_str());

    // Otherwise redirect incoming ingress UE IP to default gw
    // cmd = fmt::format("/sbin/sysctl -w net.ipv4.conf.tun{}.send_redirects=0",
    // index); rc = system ((const char*)cmd.c_str()); cmd =
    // fmt::format("/sbin/sysctl -w net.ipv4.conf.tun{}.accept_redirects=0",
    // index); rc = system ((const char*)cmd.c_str());

    if (index == 0) {
      // One queue per thread. The kernel hashes each packet's flow and always
      // puts a given flow in the same queue, so the thread that owns it is the
      // only one that ever sees that flow -- ordering costs nothing and the
      // threads no longer contend on one queue's lock. O_NONBLOCK lets the
      // reader drain with one syscall per packet instead of poll()+read().
      cmd = fmt::format("tun{}", index);
      for (int q = 0; q < nt; q++) {
        const int fd =
            tun_open((char*) cmd.c_str(), O_RDWR | O_NONBLOCK, nt > 1);
        if (fd == RETURNerror) {
          Logger::pfcp_switch().error(
              "Could not open tun%d queue %d of %d", index, q, nt);
          sleep(2);
          exit(EXIT_FAILURE);
        }
        tun_fds_.push_back(fd);
      }
      sock_r = tun_fds_[0];
      sock_w = tun_fds_[0];

      const std::vector<int> cpus =
          nt > 1 ? udp_server::datapath_cpus(nt) : std::vector<int>{};
      std::string where;
      for (int c : cpus)
        where.append(where.empty() ? " on CPU " : ",")
            .append(std::to_string(c));
      Logger::pfcp_switch().info(
          "tun%d: %d receive thread(s), one queue each%s", index, nt,
          where.c_str());
      for (int q = 0; q < nt; q++) {
        oai::utils::thread_sched_params sp = upf_cfg.n6.thread_rd_sched_params;
        if (!cpus.empty()) sp.cpu_id = cpus[q];
        prThreads_.emplace_back(
            &pfcp_switch::pdn_read_loop, this, tun_fds_[q], q, sp);
      }
      socks_r_ptr[index] = sock_r;
    }
  }

  // Disable filtering for cluster deployement
  // rc = system("/sbin/sysctl -w net.ipv4.conf.all.forwarding=1");
  // rc = system("/sbin/sysctl -w net.ipv4.conf.all.send_redirects=0");
  // rc = system("/sbin/sysctl -w net.ipv4.conf.default.send_redirects=0");
  // rc = system("/sbin/sysctl -w net.ipv4.conf.all.accept_redirects=0");
  // rc = system("/sbin/sysctl -w net.ipv4.conf.default.accept_redirects=0");
}

// =============================================================================
// Constructor / destructor
// =============================================================================

//------------------------------------------------------------------------------
// generate_fteid_n3 — allocate a new local N3 F-TEID (§8.2.3, V17.10.0).
//------------------------------------------------------------------------------
pfcp::fteid_t pfcp_switch::generate_fteid_n3() {
  pfcp::fteid_t fteid = {};
  fteid.teid          = generate_teid_n3();
  if (upf_cfg.n3.addr4.s_addr) {
    fteid.v4                  = 1;
    fteid.ipv4_address.s_addr = upf_cfg.n3.addr4.s_addr;
  } else {
    fteid.v6           = 1;
    fteid.ipv6_address = upf_cfg.n3.addr6;
  }
  return fteid;
}

//------------------------------------------------------------------------------
pfcp_switch::pfcp_switch()
    : seid_generator_(),
      teid_n3_generator__(),
      up_seid2pfcp_sessions(PFCP_SWITCH_MAX_SESSIONS, rcu_),
      ul_n3_teid2pfcp_pdr(PFCP_SWITCH_MAX_PDRS, rcu_),
      ue_ipv4_hbo2pfcp_pdr(PFCP_SWITCH_MAX_PDRS, rcu_),
      sock_w(0) {
  bool isBpfAccelerationEnabled = upf_cfg.enable_bpf_datapath;
  socks_r_ptr                   = new int[16];
  prThreadToCancel              = (pthread_t) 0;

  if (!isBpfAccelerationEnabled) {
    timer_min_commit_interval_id = 0;
    timer_max_commit_interval_id = 0;
    cp_fseid2pfcp_sessions = {}, sock_w = -1;
    pdn_if_index = -1;
    setup_pdn_interfaces();

    // Usage reporting for the simple switch. The BPF datapath measures in
    // urr_config_map and reports from its own path, so this thread is only
    // started here.
    if (upf_cfg.enable_urr) {
      thread_usage_report_ = std::thread(&pfcp_switch::usage_report_loop, this);
    }
  }
}

//------------------------------------------------------------------------------
pfcp_switch::~pfcp_switch() {
  int res;

  for (int index = 0; index < upf_cfg.pdns.size(); index++) {
    shutdown(socks_r_ptr[index], SHUT_RDWR);
  }
  for (auto& t : prThreads_) {
    if (t.joinable()) {
      res = pthread_cancel(t.native_handle());
      if (res != 0) {
        Logger::pfcp_switch().error("could not cancel pdn_read thread");
      }
    }
  }
  for (auto& t : prThreads_) {
    if (t.joinable()) t.join();
  }
  usage_report_stop_.store(true, std::memory_order_relaxed);
  if (thread_usage_report_.joinable()) thread_usage_report_.join();
  for (int fd : tun_fds_) close(fd);
  delete[] socks_r_ptr;
}

// =============================================================================
// Session / PDR hash-table helpers
// =============================================================================

//------------------------------------------------------------------------------
bool pfcp_switch::get_pfcp_session_by_cp_fseid(
    const pfcp::fseid_t& fseid,
    std::shared_ptr<pfcp::pfcp_session>& session) const {
  std::unordered_map<
      fseid_t, std::shared_ptr<pfcp::pfcp_session>>::const_iterator sit =
      cp_fseid2pfcp_sessions.find(fseid);
  if (sit == cp_fseid2pfcp_sessions.end()) return false;
  session = sit->second;
  return true;
}

//------------------------------------------------------------------------------
bool pfcp_switch::get_pfcp_session_by_up_seid(
    const uint64_t cp_seid,
    std::shared_ptr<pfcp::pfcp_session>& session) const {
  oai::upf::rcu_guard g(rcu_);
  const auto* v = up_seid2pfcp_sessions.find(cp_seid);
  if (!v) return false;
  session = *v;  // control-plane caller wants ownership
  return true;
}

//------------------------------------------------------------------------------
bool pfcp_switch::get_pfcp_ul_pdrs_by_up_teid(
    const teid_t teid,
    std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>& pdrs) const {
  oai::upf::rcu_guard g(rcu_);
  const auto* v = ul_n3_teid2pfcp_pdr.find(teid);
  if (!v) return false;
  pdrs = *v;
  return true;
}

//------------------------------------------------------------------------------
bool pfcp_switch::get_pfcp_dl_pdrs_by_ue_ip(
    const uint32_t ue_ip,
    std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>& pdrs) const {
  oai::upf::rcu_guard g(rcu_);
  const auto* v = ue_ipv4_hbo2pfcp_pdr.find(ue_ip);
  if (!v) return false;
  pdrs = *v;
  return true;
}

//------------------------------------------------------------------------------
void pfcp_switch::add_pfcp_session_by_cp_fseid(
    const pfcp::fseid_t& fseid, std::shared_ptr<pfcp::pfcp_session>& session) {
  std::pair<fseid_t, std::shared_ptr<pfcp::pfcp_session>> entry(fseid, session);
  cp_fseid2pfcp_sessions.insert(entry);
}

//------------------------------------------------------------------------------
// send_usage_report -- 3GPP TS 29.244 §7.5.8, Usage Report within a Session
// Report Request.
//
// Reports the volume accumulated since the previous report, not a running
// total: the SMF sums the deltas, and a delta stays correct across a restart
// of either end in a way a cumulative counter does not.
//------------------------------------------------------------------------------
bool pfcp_switch::send_usage_report(
    std::shared_ptr<pfcp::pfcp_session>& session, bool periodic) {
  if (!session) return false;

  // The periodic thread and session teardown can both land here for the same
  // session. Reading the counters, moving the watermark and taking a sequence
  // number have to happen as one step, or two reports overlap and the SMF
  // either double-counts a delta or never sees one.
  std::lock_guard<std::mutex> lk(session->report_mutex);

  const uint64_t ul  = session->ul_octets.load(std::memory_order_relaxed);
  const uint64_t dl  = session->dl_octets.load(std::memory_order_relaxed);
  const uint64_t ulp = session->ul_packets.load(std::memory_order_relaxed);
  const uint64_t dlp = session->dl_packets.load(std::memory_order_relaxed);

  const uint64_t d_ul  = ul - session->reported_ul_octets;
  const uint64_t d_dl  = dl - session->reported_dl_octets;
  const uint64_t d_ulp = ulp - session->reported_ul_packets;
  const uint64_t d_dlp = dlp - session->reported_dl_packets;

  // Nothing moved: a report saying zero tells the SMF nothing it cannot
  // already assume, and one per session per period would be pure noise.
  if (d_ul == 0 && d_dl == 0) return false;

  pfcp::pfcp_session_report_request h;

  pfcp::report_type_t report = {};
  report.usar                = 1;  // Usage Report -- §8.2.21
  h.set(report);

  pfcp::usage_report_within_pfcp_session_report_request ur = {};

  // One URR per session is what the SMF creates here; if it sent several we
  // still have a single set of counters, so report against the first.
  pfcp::urr_id_t urr_id = {};
  if (!session->urrs.empty() && session->urrs[0] &&
      session->urrs[0]->urr_id.first) {
    urr_id = session->urrs[0]->urr_id.second;
  }
  ur.set(urr_id);

  pfcp::ur_seqn_t seqn = {};
  seqn.ur_seqn         = session->ur_seqn++;
  ur.set(seqn);

  pfcp::usage_report_trigger_t trigger = {};
  if (periodic) {
    trigger.perio = 1;  // periodic reporting
  } else {
    trigger.immer = 1;  // immediate report (session teardown / query)
  }
  ur.set(trigger);

  pfcp::volume_measurement_t vol = {};
  vol.tovol                      = 1;
  vol.ulvol                      = 1;
  vol.dlvol                      = 1;
  vol.tonop                      = 1;
  vol.ulnop                      = 1;
  vol.dlnop                      = 1;
  vol.total_volume               = d_ul + d_dl;
  vol.uplink_volume              = d_ul;
  vol.downlink_volume            = d_dl;
  vol.total_nop                  = d_ulp + d_dlp;
  vol.uplink_nop                 = d_ulp;
  vol.downlink_nop               = d_dlp;
  ur.set(vol);

  pfcp::duration_measurement_t dur = {};
  dur.duration =
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::steady_clock::now() - session->measurement_start)
          .count();
  ur.set(dur);

  h.set(ur);

  // Advance the watermark only once the message is handed to N4. The counters
  // keep climbing underneath; taking the delta against the values read at the
  // top means traffic during this call is counted next time, never dropped.
  session->reported_ul_octets  = ul;
  session->reported_dl_octets  = dl;
  session->reported_ul_packets = ulp;
  session->reported_dl_packets = dlp;

  upf_n4_inst->send_n4_msg(session->cp_fseid, h);

  Logger::pfcp_switch().debug(
      "Usage Report seid 0x%lx: ul=%lu B (%lu pkt) dl=%lu B (%lu pkt)",
      session->seid, d_ul, d_ulp, d_dl, d_dlp);
  return true;
}

//------------------------------------------------------------------------------
// usage_report_loop -- one thread for every session, not one per session.
//
// Reporting is a control-plane rate: a handful of messages per session per
// minute. A thread each would cost more in stacks and scheduler pressure than
// the reports are worth, so this walks the session table on a fixed tick.
//------------------------------------------------------------------------------
void pfcp_switch::usage_report_loop() {
  // §8.2.42 Measurement Period is per URR; the SMF in this deployment does not
  // send one, so fall back to a period that is frequent enough to be useful
  // and rare enough to be invisible.
  constexpr int kPeriodSeconds = 30;

  while (!usage_report_stop_.load(std::memory_order_relaxed)) {
    // One-second ticks, so shutdown does not wait out a whole period.
    for (int i = 0; i < kPeriodSeconds; i++) {
      std::this_thread::sleep_for(std::chrono::seconds(1));
      if (usage_report_stop_.load(std::memory_order_relaxed)) return;
    }
    if (!upf_cfg.enable_urr) continue;

    std::vector<std::shared_ptr<pfcp::pfcp_session>> snapshot;
    up_seid2pfcp_sessions.for_each(
        [&snapshot](
            const uint64_t&, const std::shared_ptr<pfcp::pfcp_session>& v) {
          if (v) snapshot.push_back(v);
        });
    for (auto& sess : snapshot) send_usage_report(sess, true);
  }
}

//------------------------------------------------------------------------------
// apply_qos_mbr / release_qos_mbr -- QER Maximum Bitrate enforcement.
//
// A QER carries the MBR (3GPP TS 29.244 §8.2.8) and QFI (§8.2.89); the
// downlink TEID that identifies the flow on the wire comes from the FAR's
// Outer Header Creation. Pair them up and hand the rate to the policer.
// Nothing is attached to the interface until a session actually has a rate.
//------------------------------------------------------------------------------
void pfcp_switch::apply_qos_mbr(std::shared_ptr<pfcp::pfcp_session>& session) {
  if (!upf_cfg.enable_qos || upf_cfg.enable_bpf_datapath || !session) return;

  // Several QERs can bound one session (a session-AMBR one plus per-flow
  // ones). Take the tightest in each direction: whichever limit is lowest is
  // the one the session must not exceed, and picking any other would let it
  // through.
  uint64_t ul_mbr = 0;
  uint64_t dl_mbr = 0;
  uint8_t qfi     = session->qfi;
  for (const auto& q : session->qers) {
    if (!q) continue;
    if (q->maximum_bitrate.first) {
      // PFCP expresses MBR in kbit/s (§8.2.8).
      const uint64_t ul = q->maximum_bitrate.second.ul_mbr * 1000ULL;
      const uint64_t dl = q->maximum_bitrate.second.dl_mbr * 1000ULL;
      if (ul > 0 && (ul_mbr == 0 || ul < ul_mbr)) ul_mbr = ul;
      if (dl > 0 && (dl_mbr == 0 || dl < dl_mbr)) dl_mbr = dl;
    }
    if (q->qos_flow_id.first) qfi = q->qos_flow_id.second.qfi;
  }

  std::vector<oai::upf::qos_mbr::teid_rate> uplink, downlink;

  // Downlink: the TEID the packet will carry towards the gNB comes from the
  // FAR's Outer Header Creation. The uplink FAR has none, so this naturally
  // picks out the downlink ones.
  for (const auto& f : session->fars) {
    if (!f || !f->forwarding_parameters.first) continue;
    const auto& fp = f->forwarding_parameters.second;
    if (!fp.outer_header_creation.first) continue;
    const uint32_t teid = fp.outer_header_creation.second.teid;
    if (teid != 0) downlink.push_back({teid, dl_mbr});
  }

  // Uplink: the TEID arriving from the gNB is the one this UPF allocated and
  // reported in the PDI's local F-TEID. Metering it on ingress drops an
  // over-limit packet before the UPF spends anything decapsulating it.
  for (const auto& p : session->pdrs) {
    if (!p || !p->pdi.first) continue;
    const auto& pdi = p->pdi.second;
    if (!pdi.local_fteid.first) continue;
    const uint32_t teid = pdi.local_fteid.second.teid;
    if (teid != 0) uplink.push_back({teid, ul_mbr});
  }

  Logger::pfcp_switch().debug(
      "QoS/MBR: seid 0x%lx has %zu QER(s), ul_mbr=%lu dl_mbr=%lu bps, "
      "%zu uplink + %zu downlink TEID(s), qfi=%u",
      session->seid, session->qers.size(), ul_mbr, dl_mbr, uplink.size(),
      downlink.size(), qfi);

  oai::upf::qos_mbr::instance().set_rates(
      upf_cfg.n3.if_name, session->seid, uplink, downlink);
}

//------------------------------------------------------------------------------
void pfcp_switch::release_qos_mbr(
    std::shared_ptr<pfcp::pfcp_session>& session) {
  if (session) oai::upf::qos_mbr::instance().clear_rates(session->seid);
}

//------------------------------------------------------------------------------
void pfcp_switch::add_pfcp_session_by_up_seid(
    const uint64_t seid, std::shared_ptr<pfcp::pfcp_session>& session) {
  up_seid2pfcp_sessions.insert(seid, session);
}

//------------------------------------------------------------------------------
void pfcp_switch::remove_pfcp_session(
    std::shared_ptr<pfcp::pfcp_session>& session) {
  // Last chance to account for this session: whatever it moved since the
  // previous periodic report would otherwise be lost with it.
  if (upf_cfg.enable_urr && !upf_cfg.enable_bpf_datapath) {
    send_usage_report(session, false);
  }
  release_qos_mbr(session);
  session->cleanup();
  cp_fseid2pfcp_sessions.erase(session->cp_fseid);
  up_seid2pfcp_sessions.erase(session->seid);
}

//------------------------------------------------------------------------------
void pfcp_switch::remove_pfcp_session(const pfcp::fseid_t& cp_fseid) {
  std::shared_ptr<pfcp::pfcp_session> session = {};
  if (get_pfcp_session_by_cp_fseid(cp_fseid, session)) {
    remove_pfcp_session(session);
  }
}

//------------------------------------------------------------------------------
// add_pfcp_ul_pdr_by_up_teid — insert PDR into sorted-by-precedence vector.
// Creates the entry if the TEID is new; inserts in-order if TEID already
// exists.

//------------------------------------------------------------------------------
void pfcp_switch::add_pfcp_ul_pdr_by_up_teid(
    const teid_t teid, std::shared_ptr<pfcp::pfcp_pdr>& pdr) {
  // Copy-on-write. The old code push_back()ed into the live vector while
  // datapath threads were iterating it -- a race that no amount of reference
  // counting fixed, because the shared_ptr protected the vector object, not
  // its contents. Building a new vector and publishing it means a reader
  // always sees one immutable, internally consistent list; the old one is
  // freed by the RCU domain once those readers have finished with it.
  auto fresh = std::make_shared<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>();
  {
    oai::upf::rcu_guard g(rcu_);
    const auto* cur = ul_n3_teid2pfcp_pdr.find(teid);
    if (cur) *fresh = **cur;  // copy the existing entries
  }
  // Keep the vector ordered by precedence, using pfcp_pdr::operator< exactly
  // as the original did: insert before the first entry that compares less.
  // The original returned without inserting when no such entry existed, so a
  // PDR that sorted last was silently dropped; appending fixes that.
  auto it = fresh->begin();
  while (it != fresh->end() && !(*(*it) < *pdr)) ++it;
  fresh->insert(it, pdr);
  ul_n3_teid2pfcp_pdr.insert(teid, fresh);
}

//------------------------------------------------------------------------------
// remove_pdr_from_lookup -- take one PDR out of the table that feeds it.
//
// A PFCP Remove PDR used to take the rule out of the session and stop there,
// so the TEID and UE-IP tables kept forwarding through it until the whole
// session was deleted. Publishing a new vector without that PDR closes the
// window without one: readers hold an rcu_guard and see either list whole.
//------------------------------------------------------------------------------
void pfcp_switch::remove_pdr_from_lookup(
    const std::shared_ptr<pfcp::pfcp_pdr>& pdr) {
  if (!pdr || !pdr->pdi.first || !pdr->pdi.second.source_interface.first)
    return;
  const auto& pdi = pdr->pdi.second;

  if (pdi.source_interface.second.interface_value == INTERFACE_VALUE_ACCESS &&
      pdi.local_fteid.first) {
    const teid_t teid = pdi.local_fteid.second.teid;
    auto fresh =
        std::make_shared<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>();
    {
      oai::upf::rcu_guard g(rcu_);
      const auto* cur = ul_n3_teid2pfcp_pdr.find(teid);
      if (cur) {
        for (const auto& p : **cur)
          if (p != pdr) fresh->push_back(p);
      }
    }
    if (fresh->empty())
      remove_pfcp_ul_pdrs_by_up_teid(teid);
    else
      ul_n3_teid2pfcp_pdr.insert(teid, fresh);

  } else if (
      pdi.source_interface.second.interface_value == INTERFACE_VALUE_CORE &&
      pdi.ue_ip_address.first && pdi.ue_ip_address.second.v4) {
    const uint32_t ue_ip =
        be32toh(pdi.ue_ip_address.second.ipv4_address.s_addr);
    auto fresh =
        std::make_shared<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>();
    {
      oai::upf::rcu_guard g(rcu_);
      const auto* cur = ue_ipv4_hbo2pfcp_pdr.find(ue_ip);
      if (cur) {
        for (const auto& p : **cur)
          if (p != pdr) fresh->push_back(p);
      }
    }
    if (fresh->empty())
      remove_pfcp_dl_pdrs_by_ue_ip(ue_ip);  // also drops any framed routes
    else
      ue_ipv4_hbo2pfcp_pdr.insert(ue_ip, fresh);
  }
}

//------------------------------------------------------------------------------
// replace_pdr_in_lookup -- point the tables at an updated PDR.
//
// The key lives in the PDI, so an Update PDR can move the rule to a different
// TEID or UE address. Under the same key one publish swaps the rule and a
// reader never sees it missing; across keys the new entry goes in first, so
// the flow stays reachable while the old one is retired.
//------------------------------------------------------------------------------
void pfcp_switch::replace_pdr_in_lookup(
    const std::shared_ptr<pfcp::pfcp_pdr>& old_pdr,
    const std::shared_ptr<pfcp::pfcp_pdr>& new_pdr) {
  if (!old_pdr || !new_pdr) return;

  const auto key_of = [](const std::shared_ptr<pfcp::pfcp_pdr>& p, bool& is_ul,
                         teid_t& teid, uint32_t& ue_ip) {
    is_ul = false;
    teid  = 0;
    ue_ip = 0;
    if (!p->pdi.first || !p->pdi.second.source_interface.first) return false;
    const auto& pdi = p->pdi.second;
    if (pdi.source_interface.second.interface_value == INTERFACE_VALUE_ACCESS &&
        pdi.local_fteid.first) {
      is_ul = true;
      teid  = pdi.local_fteid.second.teid;
      return true;
    }
    if (pdi.source_interface.second.interface_value == INTERFACE_VALUE_CORE &&
        pdi.ue_ip_address.first && pdi.ue_ip_address.second.v4) {
      ue_ip = be32toh(pdi.ue_ip_address.second.ipv4_address.s_addr);
      return true;
    }
    return false;
  };

  bool o_ul = false, n_ul = false;
  teid_t o_teid = 0, n_teid = 0;
  uint32_t o_ip = 0, n_ip = 0;
  const bool o_keyed = key_of(old_pdr, o_ul, o_teid, o_ip);
  const bool n_keyed = key_of(new_pdr, n_ul, n_teid, n_ip);

  if (!n_keyed) {  // the update left it with no key of its own
    if (o_keyed) remove_pdr_from_lookup(old_pdr);
    return;
  }

  // Same key: one copy-on-write publish with the old rule swapped out.
  if (o_keyed && o_ul == n_ul &&
      ((n_ul && o_teid == n_teid) || (!n_ul && o_ip == n_ip))) {
    auto fresh =
        std::make_shared<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>();
    {
      oai::upf::rcu_guard g(rcu_);
      const auto* cur = n_ul ? ul_n3_teid2pfcp_pdr.find(n_teid) :
                               ue_ipv4_hbo2pfcp_pdr.find(n_ip);
      if (cur) {
        for (const auto& p : **cur)
          fresh->push_back(p == old_pdr ? new_pdr : p);
      }
    }
    if (fresh->empty()) fresh->push_back(new_pdr);
    if (n_ul)
      ul_n3_teid2pfcp_pdr.insert(n_teid, fresh);
    else
      ue_ipv4_hbo2pfcp_pdr.insert(n_ip, fresh);
    return;
  }

  // The key moved: file it under the new one before retiring the old.
  if (n_ul) {
    auto p = new_pdr;
    add_pfcp_ul_pdr_by_up_teid(n_teid, p);
  } else {
    auto p = new_pdr;
    add_pfcp_dl_pdr_by_ue_ip(n_ip, p);
  }
  if (o_keyed) remove_pdr_from_lookup(old_pdr);
}

//------------------------------------------------------------------------------
void pfcp_switch::remove_pfcp_ul_pdrs_by_up_teid(const teid_t teid) {
  ul_n3_teid2pfcp_pdr.erase(teid);
}

//------------------------------------------------------------------------------
void pfcp_switch::add_pfcp_dl_pdr_by_ue_ip(
    const uint32_t ue_ip, std::shared_ptr<pfcp::pfcp_pdr>& pdr) {
  // Same copy-on-write rule as the uplink side. Note the previous code
  // replaced the whole entry for a repeat UE IP, so a single-PDR vector
  // preserves that behaviour.
  auto fresh = std::make_shared<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>();
  fresh->push_back(pdr);
  const bool is_new = (ue_ipv4_hbo2pfcp_pdr.find(ue_ip) == nullptr);
  ue_ipv4_hbo2pfcp_pdr.insert(ue_ip, fresh);
  if (is_new && !upf_cfg.enable_bpf_datapath && upf_cfg.enable_fr &&
      pdr->pdi.second.framed_route.first) {
    for (const auto& item : pdr->pdi.second.framed_route.second) {
      Logger::pfcp_switch().debug("framed routing ip: %s", item.framed_route);
      fr->addFramedRoute(ue_ip, item);
    }
  }
}

//------------------------------------------------------------------------------
void pfcp_switch::remove_pfcp_dl_pdrs_by_ue_ip(const uint32_t ue_ip) {
  ue_ipv4_hbo2pfcp_pdr.erase(ue_ip);
  if (!upf_cfg.enable_bpf_datapath && upf_cfg.enable_fr) {
    this->fr->remove_entry(ue_ip);
  }
}

//------------------------------------------------------------------------------
std::string pfcp_switch::to_string() const {
  std::string s = {};
  up_seid2pfcp_sessions.for_each(
      [&s](const uint64_t&, const std::shared_ptr<pfcp::pfcp_session>& v) {
        s.append(v->to_string());
      });
  return s;
}

//------------------------------------------------------------------------------
bool pfcp_switch::create_packet_in_access(
    std::shared_ptr<pfcp::pfcp_pdr>& pdr, const pfcp::fteid_t& in,
    uint8_t& cause) {
  cause = CAUSE_VALUE_REQUEST_ACCEPTED;
  add_pfcp_ul_pdr_by_up_teid(in.teid, pdr);
  return true;
}

// =============================================================================
// BPF datapath bridge
// =============================================================================

//------------------------------------------------------------------------------
// call_datapath — invoke a SessionManager CRUD function asynchronously.
// Creates a snapshot copy of the pfcp_session so the datapath is not racing
// against N4 modification events on the live session object.

//------------------------------------------------------------------------------
void pfcp_switch::call_datapath(
    itti_n4_session_establishment_request* establishment_request,
    itti_n4_session_modification_request* modification_request,
    itti_n4_session_deletion_request* deletion_request, pfcp::pfcp_session* s,
    std::shared_ptr<SessionManager> obj,
    SessionOperationResult (SessionManager::*crud_func)(
        std::shared_ptr<pfcp::pfcp_session>,
        itti_n4_session_establishment_request*,
        itti_n4_session_modification_request*,
        itti_n4_session_deletion_request*)) {
  std::shared_ptr<pfcp::pfcp_session> pSession =
      std::make_shared<pfcp::pfcp_session>(*s);

  SessionOperationResult result = (obj.get()->*crud_func)(
      pSession, establishment_request, modification_request, deletion_request);

  // Optional: Log errors
  if (!result.success) {
    Logger::pfcp_switch().error(
        "Datapath operation failed: %s (SEID: 0x%lx)", result.message.c_str(),
        result.seid);
  }
}

// =============================================================================
// N4 session event handlers (3GPP TS 29.244 V17.10.0 §7.5)
// =============================================================================

//------------------------------------------------------------------------------
// handle_pfcp_session_establishment_request — 3GPP TS 29.244 V17.10.0 §7.5.2
// Creates a new pfcp_session, processes Create FAR/PDR/QER IEs, allocates
// an N3 F-TEID (§8.2.3) for uplink PDRs, then registers the session in both
// hash maps (keyed by CP F-SEID §8.2.37 and locally-generated UP SEID).

//------------------------------------------------------------------------------
void pfcp_switch::handle_pfcp_session_establishment_request(
    std::shared_ptr<itti_n4_session_establishment_request> sreq,
    itti_n4_session_establishment_response* resp) {
  bool isBpfAccelerationEnabled = upf_cfg.enable_bpf_datapath;

  itti_n4_session_establishment_request* req = sreq.get();
  pfcp::fseid_t fseid                        = {};
  pfcp::cause_t cause = {.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED};
  pfcp::offending_ie_t offending_ie = {};

  if (req->pfcp_ies.get(fseid)) {  // CP F-SEID §8.2.37 — mandatory IE
    std::shared_ptr<pfcp::pfcp_session> s = {};
    bool exist            = get_pfcp_session_by_cp_fseid(fseid, s);
    pfcp_session* session = nullptr;
    if (not exist) {
      session = new pfcp_session(fseid, generate_seid());

      // ---- Create FARs first (PDR create_far look-up requires them) --------
      for (auto it : req->pfcp_ies.create_fars) {
        create_far& cr_far = it;
        if (not session->create(cr_far, cause, offending_ie.offending_ie)) {
          session->cleanup();
          delete session;
          break;
        }
      }

      // ---- Create PDRs (allocates N3 F-TEID for ACCESS PDRs) ---------------
      if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
        //--------------------------------
        // Process PDR to be created
        cause.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
        for (auto it : req->pfcp_ies.create_pdrs) {
          create_pdr& cr_pdr            = it;
          pfcp::fteid_t allocated_fteid = {};

          pfcp::far_id_t far_id = {};
          if (not cr_pdr.get(far_id)) {
            // should be caught in lower layer
            cause.cause_value         = CAUSE_VALUE_MANDATORY_IE_MISSING;
            offending_ie.offending_ie = PFCP_IE_FAR_ID;
            session->cleanup();
            delete session;
            break;
          }
          // create pdr after create far
          pfcp::create_far cr_far = {};
          if (not req->pfcp_ies.get(far_id, cr_far)) {
            // should be caught in lower layer
            cause.cause_value         = CAUSE_VALUE_MANDATORY_IE_MISSING;
            offending_ie.offending_ie = PFCP_IE_CREATE_FAR;
            session->cleanup();
            delete session;
            break;
          }

          // QERs are parsed whenever QoS is enabled, for either datapath.
          // The simple switch enforces the Maximum Bitrate with a token bucket
          // on TC egress (see qos_mbr.hpp); it used to skip QER IEs entirely
          // because only the BPF datapath could act on them.
          if (upf_cfg.enable_qos) {
            pfcp::qer_id_t qer_id = {};
            if (cr_pdr.get(qer_id)) {
              pfcp::create_qer cr_qer = {};
              if (not req->pfcp_ies.get(qer_id, cr_qer)) {
                cause.cause_value         = CAUSE_VALUE_CONDITIONAL_IE_MISSING;
                offending_ie.offending_ie = PFCP_IE_CREATE_QER;
              }
              session->create(cr_qer, cause, offending_ie.offending_ie);
            }
          }

          if (not session->create(
                  cr_pdr, cause, offending_ie.offending_ie, allocated_fteid)) {
            session->cleanup();
            delete session;
            if (cause.cause_value == CAUSE_VALUE_CONDITIONAL_IE_MISSING) {
              resp->pfcp_ies.set(offending_ie);
            }
            resp->pfcp_ies.set(cause);
            break;
          }
          if (allocated_fteid.v4 || allocated_fteid.v6) {
            pfcp::created_pdr created_pdr = {};
            created_pdr.set(cr_pdr.pdr_id.second);
            created_pdr.set(allocated_fteid);
            resp->pfcp_ies.set(created_pdr);
          }
        }
      }

      // ---- Create URRs (BPF only) — §7.5.2.4 Create URR IE ----------------
      // pfcp_session::create(urr) populates session->urrs so that
      // SessionProgramManager::CreatePipeline can populate urr_config_map and
      // urr_volume_counters_map in the BPF program.
      // enable_urr gate: when URR is disabled, skip SMF-sent Create URR IEs
      // (Open5GS/Free5GC SMFs send URRs regardless of the UPF's local setting).
      if (upf_cfg.enable_urr) {
        if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
          for (auto it : req->pfcp_ies.create_urrs) {
            create_urr& cr_urr = it;
            if (not session->create(cr_urr, cause, offending_ie.offending_ie)) {
              Logger::upf_app().error(
                  "Establish: create(urr) failed, cause=%u", cause.cause_value);
              break;
            }
          }
        }
      }

      // ---- Create BARs (BPF only) — §7.5.2.6 Create BAR IE ----------------
      // pfcp_session::create(bar) populates session->bars so that
      // SessionProgramManager::CreatePipeline can populate bar_config_map.
      // enable_bar gate: skip BAR handling when buffering is disabled.
      if (isBpfAccelerationEnabled && upf_cfg.enable_bar) {
        if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
          // common-src: req->pfcp_ies.create_bar is singular std::pair.
          if (req->pfcp_ies.create_bar.first) {
            const create_bar& cr_bar = req->pfcp_ies.create_bar.second;
            if (not session->create(cr_bar, cause, offending_ie.offending_ie)) {
              Logger::upf_app().error(
                  "Establish: create(bar) failed, cause=%u", cause.cause_value);
            }
          }
        }
      }

      // ---- Create MARs (BPF only) — §7.5.2.8 Create MAR IE ----------------
      // pfcp_session::create(mar) populates session->mars so that
      // SessionProgramManager::CreatePipeline can populate mar_rules_map.

      // enable_mar gate: skip MAR handling when multi-access steering is
      // disabled.
      if (isBpfAccelerationEnabled && upf_cfg.enable_mar) {
        if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
          for (auto it : req->pfcp_ies.create_mars) {
            create_mar& cr_mar = it;
            if (not session->create(cr_mar, cause, offending_ie.offending_ie)) {
              Logger::upf_app().error(
                  "Establish: create(mar) failed, cause=%u", cause.cause_value);
              break;
            }
          }
        }
      }

      if (isBpfAccelerationEnabled) {
        Logger::upf_app().info(
            "Establish datapath: create(pdr(s), far(s), qer(s), urr(s), "
            "bar(s), mar(s))");
        call_datapath(
            req, nullptr, nullptr, session, session_manager,
            &SessionManager::EstablishSession);
      }

      if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
        s = std::shared_ptr<pfcp_session>(session);
        add_pfcp_session_by_cp_fseid(fseid, s);
        add_pfcp_session_by_up_seid(session->seid, s);
        apply_qos_mbr(s);
        // start_timer_min_commit_interval();
        // start_timer_max_commit_interval();

        pfcp::fseid_t up_fseid = {};
        upf_cfg.get_pfcp_fseid(up_fseid);
        up_fseid.seid = session->get_up_seid();
        resp->pfcp_ies.set(up_fseid);

        // Register session
        pfcp::node_id_t node_id = {};
        req->pfcp_ies.get(node_id);  // Node ID §8.2.38 — optional in response
        pfcp_associations::get_instance().notify_add_session(node_id, fseid);
      }
    } else {
      cause.cause_value = CAUSE_VALUE_REQUEST_REJECTED;
    }
  } else {
    // should be caught in lower layer
    cause.cause_value         = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie.offending_ie = PFCP_IE_F_SEID;
  }

  resp->pfcp_ies.set(cause);
  if ((cause.cause_value == CAUSE_VALUE_MANDATORY_IE_MISSING) ||
      (cause.cause_value == CAUSE_VALUE_CONDITIONAL_IE_MISSING)) {
    resp->pfcp_ies.set(offending_ie);
  }

  if (Logger::should_log(spdlog::level::debug)) {
    // Print PDU session rules table
    up_seid2pfcp_sessions.for_each(
        [](const uint64_t&, const std::shared_ptr<pfcp::pfcp_session>& v) {
          std::cout << v->to_string();
        });
  }
}

//------------------------------------------------------------------------------
// handle_pfcp_session_modification_request — 3GPP TS 29.244 V17.10.0 §7.5.4
// Processes Remove/Create/Update PDR, FAR, QER, URR, BAR IEs in order.

//------------------------------------------------------------------------------
void pfcp_switch::handle_pfcp_session_modification_request(
    std::shared_ptr<itti_n4_session_modification_request> sreq,
    itti_n4_session_modification_response* resp) {
  bool isBpfAccelerationEnabled = upf_cfg.enable_bpf_datapath;

  itti_n4_session_modification_request* req = sreq.get();

  std::shared_ptr<pfcp::pfcp_session> s = {};
  pfcp::fseid_t fseid                   = {};
  pfcp::cause_t cause = {.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED};
  pfcp::offending_ie_t offending_ie = {};
  failed_rule_id_t failed_rule      = {};

  if (not get_pfcp_session_by_up_seid(req->seid, s)) {
    cause.cause_value = CAUSE_VALUE_SESSION_CONTEXT_NOT_FOUND;
  } else {
    pfcp::pfcp_session* session = s.get();
    pfcp::fseid_t fseid         = {};
    if (req->pfcp_ies.get(fseid)) {
      Logger::pfcp_switch().warn(
          "TODO check carefully update fseid in "
          "PFCP_SESSION_MODIFICATION_REQUEST");
      session->cp_fseid = fseid;
    }
    resp->seid = session->cp_fseid.seid;

    // ---- Remove PDRs --------------------------------------------------------
    for (auto it : req->pfcp_ies.remove_pdrs) {
      if (isBpfAccelerationEnabled) {
        Logger::upf_app().info("Modify datapath: remove(pdr)");
        call_datapath(
            nullptr, req, nullptr, session, session_manager,
            &SessionManager::ModifySession);
      }

      remove_pdr& pdr = it;

      // Take it out of the datapath tables first, while the rule is still
      // reachable through the session.
      std::shared_ptr<pfcp::pfcp_pdr> spdr = {};
      if (pdr.pdr_id.first && session->get(pdr.pdr_id.second.rule_id, spdr) &&
          spdr) {
        remove_pdr_from_lookup(spdr);
      }

      if (not session->remove(pdr, cause, offending_ie.offending_ie)) {
        if (cause.cause_value ==
            CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE) {
          failed_rule.rule_id_type  = FAILED_RULE_ID_TYPE_PDR;
          failed_rule.rule_id_value = pdr.pdr_id.second.rule_id;
          resp->pfcp_ies.set(failed_rule);
          break;
        }
      }
    }

    // ---- Remove FARs --------------------------------------------------------
    if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
      for (auto it : req->pfcp_ies.remove_fars) {
        if (isBpfAccelerationEnabled) {
          Logger::upf_app().info("Modify datapath: remove(far)");
          call_datapath(
              nullptr, req, nullptr, session, session_manager,
              &SessionManager::ModifySession);
        }

        remove_far& far = it;

        if (not session->remove(far, cause, offending_ie.offending_ie)) {
          if (cause.cause_value ==
              CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE) {
            failed_rule.rule_id_type  = FAILED_RULE_ID_TYPE_FAR;
            failed_rule.rule_id_value = far.far_id.second.far_id;
            resp->pfcp_ies.set(failed_rule);
            break;
          }
        }
      }
    }

    // ---- Remove QERs (BPF only) ---------------------------------------------
    // Both datapaths handle QERs: BPF via qer_config_map, the simple switch
    // via a token bucket (see apply_qos_mbr).
    if (upf_cfg.enable_qos) {
      if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
        for (auto it : req->pfcp_ies.remove_qers) {
          // Only the BPF datapath has a SessionManager to call: it is null
          // under the simple switch, so calling through it segfaults. The
          // rule removal below is what both datapaths share.
          if (isBpfAccelerationEnabled) {
            Logger::upf_app().info("Modify datapath: remove(qer)");
            call_datapath(
                nullptr, req, nullptr, session, session_manager,
                &SessionManager::ModifySession);
          }
          remove_qer& qer = it;

          if (not session->remove(qer, cause, offending_ie.offending_ie)) {
            if (cause.cause_value ==
                CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE) {
              failed_rule.rule_id_type  = FAILED_RULE_ID_TYPE_QER;
              failed_rule.rule_id_value = qer.qer_id.second.qer_id;
              resp->pfcp_ies.set(failed_rule);
              break;
            }
          }
        }
      }
    }

    // ---- Remove URRs (BPF only) — §7.5.4.8 Remove URR IE -------------------
    // Removes URR from session->urrs so the BPF urr_config_map entry is
    // cleaned up on the next ModifyPipeline call via call_datapath().
    // enable_urr gate (see establishment path).
    if (upf_cfg.enable_urr) {
      if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
        for (auto it : req->pfcp_ies.remove_urrs) {
          remove_urr& urr = it;
          if (not session->remove(urr, cause, offending_ie.offending_ie)) {
            if (cause.cause_value ==
                CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE) {
              failed_rule.rule_id_type  = FAILED_RULE_ID_TYPE_URR;
              failed_rule.rule_id_value = urr.urr_id.second.urr_id;
              resp->pfcp_ies.set(failed_rule);
              break;
            }
          }
        }
      }
    }

    // ---- Remove BARs (BPF only) — §7.5.4.10 Remove BAR IE ------------------
    // Removes BAR from session->bars so the BPF bar_config_map entry is
    // cleaned up on the next ModifyPipeline call via call_datapath().
    // enable_bar gate: skip BAR handling when buffering is disabled.
    if (isBpfAccelerationEnabled && upf_cfg.enable_bar) {
      if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
        // common-src: pfcp_ies.remove_bar is singular std::pair.
        if (req->pfcp_ies.remove_bar.first) {
          const remove_bar& bar = req->pfcp_ies.remove_bar.second;
          if (not session->remove(bar, cause, offending_ie.offending_ie)) {
            if (cause.cause_value ==
                CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE) {
              failed_rule.rule_id_type  = FAILED_RULE_ID_TYPE_BAR;
              failed_rule.rule_id_value = bar.bar_id.second.bar_id;
              resp->pfcp_ies.set(failed_rule);
            }
          }
        }
      }
    }

    // ---- Remove MARs (BPF only) — §7.5.4.15 Remove MAR IE ------------------

    // enable_mar gate: skip MAR handling when multi-access steering is
    // disabled.
    if (isBpfAccelerationEnabled && upf_cfg.enable_mar) {
      if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
        for (auto it : req->pfcp_ies.remove_mars) {
          remove_mar& mar = it;
          if (not session->remove(mar, cause, offending_ie.offending_ie)) {
            if (cause.cause_value ==
                CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE) {
              failed_rule.rule_id_type  = FAILED_RULE_ID_TYPE_MAR;
              failed_rule.rule_id_value = mar.mar_id.second.mar_id;
              resp->pfcp_ies.set(failed_rule);
              break;
            }
          }
        }
      }
    }

    // ---- Create FARs --------------------------------------------------------
    if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
      for (auto it : req->pfcp_ies.create_fars) {
        create_far& cr_far = it;
        if (not session->create(cr_far, cause, offending_ie.offending_ie)) {
          break;
        }
      }
    }

    // ---- Create PDRs --------------------------------------------------------
    if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
      for (auto it : req->pfcp_ies.create_pdrs) {
        create_pdr& cr_pdr = it;

        pfcp::far_id_t far_id = {};
        if (not cr_pdr.get(far_id)) {
          // should be caught in lower layer
          cause.cause_value         = CAUSE_VALUE_MANDATORY_IE_MISSING;
          offending_ie.offending_ie = PFCP_IE_FAR_ID;
          break;
        }
        // create pdr after create far
        pfcp::create_far cr_far = {};
        if (not req->pfcp_ies.get(far_id, cr_far)) {
          // should be caught in lower layer
          cause.cause_value         = CAUSE_VALUE_MANDATORY_IE_MISSING;
          offending_ie.offending_ie = PFCP_IE_CREATE_FAR;
          break;
        }

        pfcp::fteid_t allocated_fteid = {};
        if (not session->create(
                cr_pdr, cause, offending_ie.offending_ie, allocated_fteid)) {
          if (cause.cause_value == CAUSE_VALUE_CONDITIONAL_IE_MISSING) {
            resp->pfcp_ies.set(offending_ie);
          }
          resp->pfcp_ies.set(cause);
          break;
        }
        pfcp::created_pdr created_pdr = {};
        created_pdr.set(cr_pdr.pdr_id.second);
        if (not allocated_fteid.is_zero()) {
          created_pdr.set(allocated_fteid);
        }
        resp->pfcp_ies.set(created_pdr);
      }
    }

    // ---- Create QERs (BPF only) ---------------------------------------------
    // Both datapaths handle QERs: BPF via qer_config_map, the simple switch
    // via a token bucket (see apply_qos_mbr).
    if (upf_cfg.enable_qos) {
      if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
        for (auto it : req->pfcp_ies.create_qers) {
          create_qer& cr_qer = it;
          if (not session->create(cr_qer, cause, offending_ie.offending_ie)) {
            break;
          }
        }
      }
    }

    // ---- Create URRs (BPF only) — §7.5.4.4 Create URR IE -------------------
    // Populates session->urrs so that SessionProgramManager::ModifyPipeline
    // can write urr_config_map entries for the new URRs.
    // enable_urr gate (see establishment path).
    if (upf_cfg.enable_urr) {
      if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
        for (auto it : req->pfcp_ies.create_urrs) {
          create_urr& cr_urr = it;
          if (not session->create(cr_urr, cause, offending_ie.offending_ie)) {
            break;
          }
        }
      }
    }

    // ---- Create BARs (BPF only) — §7.5.4.6 Create BAR IE -------------------
    // Populates session->bars so that SessionProgramManager::ModifyPipeline
    // can write bar_config_map entries for the new BARs.
    // enable_bar gate: skip BAR handling when buffering is disabled.
    if (isBpfAccelerationEnabled && upf_cfg.enable_bar) {
      if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
        // common-src: pfcp_ies.create_bar is singular std::pair.
        if (req->pfcp_ies.create_bar.first) {
          const create_bar& cr_bar = req->pfcp_ies.create_bar.second;
          if (not session->create(cr_bar, cause, offending_ie.offending_ie)) {
            // create() failed; cause already set inside.
          }
        }
      }
    }

    // ---- Create MARs (BPF only) — §7.5.2.8 Create MAR IE -------------------
    // enable_mar gate: skip MAR handling when multi-access steering is
    // disabled.
    if (isBpfAccelerationEnabled && upf_cfg.enable_mar) {
      if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
        for (auto it : req->pfcp_ies.create_mars) {
          create_mar& cr_mar = it;
          if (not session->create(cr_mar, cause, offending_ie.offending_ie)) {
            break;
          }
        }
      }
    }

    // ---- Update PDRs / FARs / QERs ------------------------------------------
    if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
      for (auto it : req->pfcp_ies.update_pdrs) {
        update_pdr& pdr     = it;
        uint8_t cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
        if (not session->update(pdr, cause_value)) {
          failed_rule_id_t failed_rule = {};
          failed_rule.rule_id_type     = FAILED_RULE_ID_TYPE_PDR;
          failed_rule.rule_id_value    = pdr.pdr_id.second.rule_id;
          resp->pfcp_ies.set(failed_rule);
        }
      }
      for (auto it : req->pfcp_ies.update_fars) {
        update_far& far     = it;
        uint8_t cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
        if (not session->update(far, cause_value)) {
          cause.cause_value            = cause_value;
          failed_rule_id_t failed_rule = {};
          failed_rule.rule_id_type     = FAILED_RULE_ID_TYPE_FAR;
          failed_rule.rule_id_value    = far.far_id.far_id;
          resp->pfcp_ies.set(failed_rule);
        }
      }
      // Both datapaths handle QERs -- see the Create QER block above.
      if (upf_cfg.enable_qos) {
        for (auto it : req->pfcp_ies.update_qers) {
          update_qer& qer     = it;
          uint8_t cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
          if (not session->update(qer, cause_value)) {
            failed_rule_id_t failed_rule = {};
            failed_rule.rule_id_type     = FAILED_RULE_ID_TYPE_QER;
            failed_rule.rule_id_value    = qer.qer_id.second.qer_id;
            resp->pfcp_ies.set(failed_rule);
          }
        }
      }

      // ---- Update URRs (BPF only) — §7.5.4.11 Update URR IE ----------------
      // Updates reporting triggers, thresholds, and quotas in session->urrs.
      // urr_config_map is repopulated by ModifyPipeline;
      // urr_volume_counters_map counters are preserved (BPF_NOEXIST semantics
      // in PopulateUrrConfigMap).
      // enable_urr gate (see establishment path).
      if (upf_cfg.enable_urr) {
        for (auto it : req->pfcp_ies.update_urrs) {
          update_urr& urr     = it;
          uint8_t cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
          if (not session->update(urr, cause_value)) {
            failed_rule_id_t failed_rule = {};
            failed_rule.rule_id_type     = FAILED_RULE_ID_TYPE_URR;
            failed_rule.rule_id_value    = urr.urr_id.second.urr_id;
            resp->pfcp_ies.set(failed_rule);
          }
        }
      }

      // ---- Update BARs (BPF only) — §7.5.4.13 Update BAR IE ----------------
      // Updates DL notification delay and suggested buffering packet count.
      // bar_state_map (DDN tracking) is preserved by ModifyPipeline.
      // enable_bar gate: skip BAR handling when buffering is disabled.
      if (isBpfAccelerationEnabled && upf_cfg.enable_bar) {
        // common-src: pfcp_ies.update_bar is singular std::pair.
        if (req->pfcp_ies.update_bar.first) {
          const update_bar_within_pfcp_session_modification_request& bar =
              req->pfcp_ies.update_bar.second;
          uint8_t cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
          if (not session->update(bar, cause_value)) {
            failed_rule_id_t failed_rule = {};
            failed_rule.rule_id_type     = FAILED_RULE_ID_TYPE_BAR;
            failed_rule.rule_id_value    = bar.bar_id.second.bar_id;
            resp->pfcp_ies.set(failed_rule);
          }
        }
      }

      // ---- Update MARs (BPF only) — §7.5.4.16 Update MAR IE ----------------
      // enable_mar gate: skip MAR handling when multi-access steering is
      // disabled.
      if (isBpfAccelerationEnabled && upf_cfg.enable_mar) {
        for (auto it : req->pfcp_ies.update_mars) {
          update_mar& mar     = it;
          uint8_t cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
          if (not session->update(mar, cause_value)) {
            failed_rule_id_t failed_rule = {};
            failed_rule.rule_id_type     = FAILED_RULE_ID_TYPE_MAR;
            failed_rule.rule_id_value    = mar.mar_id.second.mar_id;
            resp->pfcp_ies.set(failed_rule);
          }
        }
      }
    }

    if (isBpfAccelerationEnabled) {
      Logger::upf_app().info("Modify datapath");
      call_datapath(
          nullptr, req, nullptr, session, session_manager,
          &SessionManager::ModifySession);
    }

    // Re-programme the rate limiters. This is the hook that matters in
    // practice: the downlink FAR only learns its Outer Header Creation TEID
    // once the gNB reports its N3 tunnel, which arrives here and not at
    // establishment.
    apply_qos_mbr(s);
  }

  resp->pfcp_ies.set(cause);
  if ((cause.cause_value == CAUSE_VALUE_MANDATORY_IE_MISSING) ||
      (cause.cause_value == CAUSE_VALUE_CONDITIONAL_IE_MISSING)) {
    resp->pfcp_ies.set(offending_ie);
  }

  if (Logger::should_log(spdlog::level::debug)) {
    // Print PDU session rules table
    up_seid2pfcp_sessions.for_each(
        [](const uint64_t&, const std::shared_ptr<pfcp::pfcp_session>& v) {
          std::cout << v->to_string();
        });
  }
}

//------------------------------------------------------------------------------
// handle_pfcp_session_deletion_request — 3GPP TS 29.244 V17.10.0 §7.5.6
// Invokes the BPF datapath removal if enabled, then removes the session from
// both hash maps and clears all tun/teid registrations via cleanup().

//------------------------------------------------------------------------------
void pfcp_switch::handle_pfcp_session_deletion_request(
    std::shared_ptr<itti_n4_session_deletion_request> sreq,
    itti_n4_session_deletion_response* resp) {
  bool isBpfAccelerationEnabled         = upf_cfg.enable_bpf_datapath;
  itti_n4_session_deletion_request* req = sreq.get();

  std::shared_ptr<pfcp::pfcp_session> s = {};
  pfcp::fseid_t fseid                   = {};
  pfcp::cause_t cause = {.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED};

  if (not get_pfcp_session_by_up_seid(req->seid, s)) {
    cause.cause_value = CAUSE_VALUE_SESSION_CONTEXT_NOT_FOUND;
  } else {
    pfcp::pfcp_session* session = s.get();
    resp->seid                  = s->cp_fseid.seid;

    if (isBpfAccelerationEnabled) {
      Logger::upf_app().info("Delete datapath");
      call_datapath(
          nullptr, nullptr, req, session, session_manager,
          &SessionManager::RemoveSession);
    }

    remove_pfcp_session(s);
  }

  pfcp_associations::get_instance().notify_del_session(fseid);
  resp->pfcp_ies.set(cause);

  if (Logger::should_log(spdlog::level::debug)) {
    // Print PDU session rules table
    up_seid2pfcp_sessions.for_each(
        [](const uint64_t&, const std::shared_ptr<pfcp::pfcp_session>& v) {
          std::cout << v->to_string();
        });
  }
}

// =============================================================================
// Per-packet data-plane look-up (hot path)
// =============================================================================

//------------------------------------------------------------------------------
// pfcp_session_look_up_pack_in_access (IPv4) — N3 uplink path.
// Looks up the TEID in ul_n3_teid2pfcp_pdr, iterates PDRs in precedence order,
// runs PDI matching, then calls pfcp_far::apply_forwarding_rules().

//------------------------------------------------------------------------------
void pfcp_switch::pfcp_session_look_up_pack_in_access(
    struct iphdr* const iph, const std::size_t num_bytes,
    const endpoint& r_endpoint, const uint32_t tunnel_id) {
  bool isInAccess = false;
  if (!upf_cfg.nsf.bypass_ul_pfcp_rules) {
    // One RCU critical section covers every pointer this packet touches.
    // Nothing below copies a shared_ptr, so the packet costs two plain stores
    // to this thread's own cache line instead of ~8 atomic RMWs on lines
    // shared with every other core.
    oai::upf::rcu_guard rg(rcu_);
    const auto* pdrs_p = find_ul_pdrs(tunnel_id);
    if (pdrs_p) {
      const auto& pdrs = *pdrs_p;
      bool nocp        = false;
      bool buff        = false;
      for (auto it_pdr = pdrs->begin(); it_pdr < pdrs->end(); ++it_pdr) {
        isInAccess = (*it_pdr)->look_up_pack_in_access(
            iph, num_bytes, r_endpoint, tunnel_id);
        if (!isInAccess && upf_cfg.enable_fr &&
            it_pdr->get()->pdi.second.framed_route.first) {
          auto fr_ue_ip   = (struct iphdr*) malloc(sizeof(struct iphdr));
          fr_ue_ip->saddr = be32toh(fr->retrieveUEIp(be32toh(iph->saddr)));
          isInAccess      = (*it_pdr)->look_up_pack_in_access(
              fr_ue_ip, num_bytes, r_endpoint, tunnel_id);
        }
        if (isInAccess) {
          // NOTE: no logging on the per-packet fast path.  These were info()
          // calls, which pass should_log() at the shipped default log level
          // (config.yaml: general: debug) and cost two fmt::sprintf plus a
          // sink write on every uplink packet.
          uint64_t lseid = 0;
          if ((*it_pdr)->get(lseid)) {
            const auto* sess_p = find_session(lseid);
            if (sess_p) {
              const auto& ssession  = *sess_p;
              pfcp::far_id_t far_id = {};
              if ((*it_pdr)->get(far_id)) {
                std::shared_ptr<pfcp::pfcp_far> sfar = {};
                if (ssession->get(far_id.far_id, sfar)) {
                  // Maintain uplink QFI in session
                  uint8_t qfi = (*it_pdr)->pdi.second.qfi.second.qfi;
                  ssession->qfi.store(qfi, std::memory_order_relaxed);
                  // Volume measured on the packet the UE actually sent, i.e.
                  // after decapsulation -- what §8.2.44 asks for and what the
                  // subscriber is billed on.
                  ssession->ul_octets.fetch_add(
                      num_bytes, std::memory_order_relaxed);
                  ssession->ul_packets.fetch_add(1, std::memory_order_relaxed);
                  sfar->apply_forwarding_rules(iph, num_bytes, nocp, buff, 0);
                }
              }
            }
            return;
          }

        } else {
          Logger::pfcp_switch().info(
              "pfcp_session_look_up_pack_in_access failed PDR id %4x ",
              (*it_pdr)->pdr_id.rule_id);
        }
      }
    } else {
      // Logger::pfcp_switch().info( "pfcp_session_look_up_pack_in_access tunnel
      // " TEID_FMT " not found", tunnel_id);
      upf_n3_inst->report_error_indication(r_endpoint, tunnel_id);
    }
  } else {
    // bypass_ul_pfcp_rules: skip PDR look-up, forward directly to core
    if (no_internal_loop(iph, num_bytes)) {
      pfcp_switch_inst->send_to_core(
          reinterpret_cast<char* const>(iph), num_bytes);
    }
  }
}

//------------------------------------------------------------------------------
bool pfcp_switch::no_internal_loop(
    struct iphdr* const iph, const std::size_t num_bytes) {
  pdn_cfg_t& pdn = upf_cfg.pdns[0];
  if ((pdn.network_ipv4.s_addr == (iph->daddr & pdn.network_mask_ipv4_be)) &&
      ((be32toh(iph->daddr) & 0x000000FF) != 0X00000001)) {
    pfcp_session_look_up_pack_in_core((const char*) iph, num_bytes);
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
// pfcp_session_look_up_pack_in_access (IPv6) — TODO

//------------------------------------------------------------------------------
void pfcp_switch::pfcp_session_look_up_pack_in_access(
    struct ipv6hdr* const ip6h, const std::size_t num_bytes,
    const endpoint& r_endpoint, const uint32_t tunnel_id) {
  // TODO: IPv6 uplink look-up
}

//------------------------------------------------------------------------------
// pfcp_session_look_up_pack_in_core — N6 downlink path.
// Looks up the destination UE IP in ue_ipv4_hbo2pfcp_pdr, iterates PDRs in
// precedence order, then calls pfcp_far::apply_forwarding_rules().

//------------------------------------------------------------------------------
void pfcp_switch::pfcp_session_look_up_pack_in_core(
    const char* buffer, const std::size_t num_bytes) {
  struct iphdr* iph = (struct iphdr*) buffer;
  std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>> pdrs;

  // See the uplink path: one critical section, no per-packet refcounting.
  oai::upf::rcu_guard rg(rcu_);

  if (iph->version == 4) {
    uint32_t ue_ip     = be32toh(iph->daddr);
    const auto* pdrs_p = find_dl_pdrs(ue_ip);
    bool is_pdr_ue_ip  = (pdrs_p != nullptr);
    if (is_pdr_ue_ip) pdrs = *pdrs_p;
    if (!is_pdr_ue_ip && upf_cfg.enable_fr) {
      uint32_t fr_ip = fr->retrieveUEIp(ue_ip);
      ue_ip          = fr_ip != 0 ? fr_ip : ue_ip;
      is_pdr_ue_ip   = get_pfcp_dl_pdrs_by_ue_ip(ue_ip, pdrs);
    }
    if (is_pdr_ue_ip) {
      bool nocp = false;
      bool buff = false;
      for (auto it = pdrs->begin(); it < pdrs->end(); ++it) {
        if ((*it)->look_up_pack_in_core(iph, num_bytes)) {
          std::shared_ptr<pfcp::pfcp_session> ssession = {};
          uint64_t lseid                               = 0;
          if ((*it)->get(lseid)) {
            if (get_pfcp_session_by_up_seid(lseid, ssession)) {
              pfcp::far_id_t far_id = {};
              if ((*it)->get(far_id)) {
                std::shared_ptr<pfcp::pfcp_far> sfar = {};
                // The QFI belongs to the flow this packet matched, so read
                // it from the matched rule, which is immutable once published.
                // Resolving it through the session's QER list instead would
                // mean walking a vector the control plane can be editing.
                // Rules that carry no QFI fall back to the session-wide value
                // learned from uplink traffic.
                uint8_t qfi = ssession->qfi.load(std::memory_order_relaxed);
                if ((*it)->pdi.first && (*it)->pdi.second.qfi.first) {
                  qfi = (*it)->pdi.second.qfi.second.qfi;
                }
                if (ssession->get(far_id.far_id, sfar)) {
                  // Counted before encapsulation, to match the uplink side.
                  ssession->dl_octets.fetch_add(
                      num_bytes, std::memory_order_relaxed);
                  ssession->dl_packets.fetch_add(1, std::memory_order_relaxed);
                  sfar->apply_forwarding_rules(iph, num_bytes, nocp, buff, qfi);
                  if (buff) {
                    (*it)->buffering_requested(buffer, num_bytes);
                  }
                  if (nocp) {
                    (*it)->notify_cp_requested(ssession);
                  }
                }
              }
            }
          }
          return;
        } else {
          Logger::pfcp_switch().info(
              "look_up_pack_in_core failed PDR id %4x ", (*it)->pdr_id.rule_id);
        }
      }
    } else {
      Logger::pfcp_switch().info(
          "pfcp_session_look_up_pack_in_core UE IP %8x not found", ue_ip);
    }
  } else if (iph->version == 6) {
    // TODO: IPv6 downlink look-up
  } else {
    Logger::pfcp_switch().info("Unknown IP version %d packet", iph->version);
  }
}
