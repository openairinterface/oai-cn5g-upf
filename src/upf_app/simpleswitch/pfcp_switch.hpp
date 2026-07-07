/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_PFCP_SWITCH_HPP_SEEN
#define FILE_PFCP_SWITCH_HPP_SEEN

#include <folly/AtomicHashMap.h>
#include <folly/MPMCQueue.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <netinet/in.h>
#include <pthread.h>
#include <thread>
#include <unordered_map>
#include <memory>
#include <variant>
#include <vector>

#include "framed_routing/FramedRouting.hpp"
#include "framed_routing/LocalRouting.hpp"
//#include "concurrentqueue.h"
#include "itti.hpp"
#include "itti_msg_n4.hpp"
#include "msg_pfcp.hpp"
#include "pfcp_session.hpp"
#include "thread_sched.hpp"
#include "uint_generator.hpp"

#include <SessionManager.h>

namespace oai {
namespace upf {
namespace app {

/// Maximum sessions tracked simultaneously
#define PFCP_SWITCH_MAX_SESSIONS 1024
/// Maximum PDR entries in each lookup table
#define PFCP_SWITCH_MAX_PDRS 1024

/** @brief iovec item used for the DL packet read/work pool queues. */
typedef struct iovec_q_item_s {
  struct iovec msg_iov;  ///< Scatter/gather buffer for recv
  struct msghdr msg;     ///< Socket message header
} iovec_q_item_t;

/** @brief Central PFCP switching engine.
 *
 *  Owns all session/PDR hash tables, the tun0 read loop, PDN worker
 *  threads, and the PFCP N4 session event handlers.
 *
 *  Thread-safety note: cp_fseid2pfcp_sessions uses std::unordered_map
 *  (not lock-free); all modifications must be serialised via the ITTI
 *  N4 task thread.  up_seid2pfcp_sessions and the teid/ue-ip maps use
 *  folly::AtomicHashMap which is lock-free for concurrent reads.
 */
class pfcp_switch {
 private:
  // Very unoptimized
#define PFCP_SWITCH_RECV_BUFFER_SIZE 2048
#define ROOM_FOR_GTPV1U_G_PDU 64

  folly::MPMCQueue<iovec_q_item_t*>* free_pool_;  ///< Pre-allocated I/O buffers
  folly::MPMCQueue<iovec_q_item_t*>*
      work_pool_;            ///< Filled buffers pending processing
  uint32_t num_threads_;     ///< DL worker thread count (currently fixed to 1)
  char* recv_buffer_alloc_;  ///< Contiguous allocation backing the free_pool_
                             ///< iov buffers
  char recv_buffer_[PFCP_SWITCH_RECV_BUFFER_SIZE];  ///< Scratch buffer (legacy;
                                                    ///< not used in pool path)

  // ---- PDN threads ---------------------------------------------------------
  std::thread pwThread_;       ///< PDN worker thread (DL packet processing)
  std::thread prThread_;       ///< PDN reader thread (tun0 read loop)
  pthread_t prThreadToCancel;  ///< pthread handle used to cancel prThread_ on
                               ///< shutdown
  int* socks_r_ptr;   ///< Array[16] of read sockets, one per PDN interface
  int sock_w;         ///< Write socket for tun0 (DL injection)
  bool terminatePW_;  ///< Shutdown flag written by destructor, read by
                      ///< pdn_worker
  // std::string                               gw_mac_address;
  int pdn_if_index;  ///< if_index of the tun0 PDN interface (N6)

  // ---- SEID / TEID generators ----------------------------------------------
  oai::utils::uint_generator<uint64_t>
      seid_generator_;  ///< Monotonic UP SEID allocator
  oai::utils::uint_generator<teid_t>
      teid_n3_generator__;  ///< Monotonic N3 GTP-U TEID allocator

#define TASK_UPF_PFCP_SWITCH_MAX_COMMIT_INTERVAL (0)
#define TASK_UPF_PFCP_SWITCH_MIN_COMMIT_INTERVAL (1)

#define PFCP_SWITCH_MAX_COMMIT_INTERVAL_MILLISECONDS 200
#define PFCP_SWITCH_MIN_COMMIT_INTERVAL_MILLISECONDS 50

  // ---- Routing helpers -----------------------------------------------------
  const std::shared_ptr<fr::LocalRouting>
      local_routing =  ///< Static routing table for framed-route UE subnets
      std::make_shared<fr::LocalRouting>();
  const std::shared_ptr<fr::FramedRouting>
      fr =  ///< Framed Routing engine (RFC 2865 Framed-Route attribute)
      std::make_shared<fr::FramedRouting>(local_routing);

  // ---- Session / PDR lookup tables ----------------------------------------

  /// CP F-SEID → session (3GPP TS 29.244 §8.2.37)
  std::unordered_map<pfcp::fseid_t, std::shared_ptr<pfcp::pfcp_session>>
      cp_fseid2pfcp_sessions;

  /// UP SEID → session (allocated locally)
  folly::AtomicHashMap<uint64_t, std::shared_ptr<pfcp::pfcp_session>>
      up_seid2pfcp_sessions;

  /// GTP-U TEID → uplink PDR vector (N3 interface, §8.2.3)
  folly::AtomicHashMap<
      teid_t, std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>>
      ul_n3_teid2pfcp_pdr;

  /// UE IPv4 (host byte order) → downlink PDR vector (§8.2.62)
  folly::AtomicHashMap<
      uint32_t, std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>>
      ue_ipv4_hbo2pfcp_pdr;

  timer_id_t timer_max_commit_interval_id;  ///< ITTI timer: maximum interval
                                            ///< between datapath commits
  timer_id_t timer_min_commit_interval_id;  ///< ITTI timer: minimum interval
                                            ///< between datapath commits

  //------------------------------------------------------------------------------
  /** @brief Stop the minimum-interval commit timer (if running). */
  void stop_timer_min_commit_interval();
  /** @brief (Re-)start the minimum-interval commit timer. */
  void start_timer_min_commit_interval();
  /** @brief Stop the maximum-interval commit timer (if running). */
  void stop_timer_max_commit_interval();
  /** @brief (Re-)start the maximum-interval commit timer. */
  void start_timer_max_commit_interval();

  /** @brief Flush pending PDR/FAR changes to the data-plane lookup tables. */
  void commit_changes();

  // ---- Private session/PDR helpers -----------------------------------------

  //------------------------------------------------------------------------------
  /** @brief Look up a session by CP F-SEID. */
  bool get_pfcp_session_by_cp_fseid(
      const pfcp::fseid_t&, std::shared_ptr<pfcp::pfcp_session>&) const;

  //------------------------------------------------------------------------------
  /** @brief Look up a session by UP SEID. */
  bool get_pfcp_session_by_up_seid(
      const uint64_t, std::shared_ptr<pfcp::pfcp_session>&) const;

  //------------------------------------------------------------------------------
  /** @brief Look up uplink PDR vector by GTP-U TEID. */
  bool get_pfcp_ul_pdrs_by_up_teid(
      const teid_t,
      std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>&) const;

  //------------------------------------------------------------------------------
  /** @brief Look up downlink PDR vector by UE IPv4 (host byte order). */
  bool get_pfcp_dl_pdrs_by_ue_ip(
      const uint32_t,
      std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>&) const;

  //------------------------------------------------------------------------------
  /** @brief Register a session in the CP F-SEID map (§8.2.37). */
  void add_pfcp_session_by_cp_fseid(
      const pfcp::fseid_t&, std::shared_ptr<pfcp::pfcp_session>&);
  /** @brief Register a session in the UP SEID map. */
  void add_pfcp_session_by_up_seid(
      const uint64_t, std::shared_ptr<pfcp::pfcp_session>&);

  //------------------------------------------------------------------------------
  /** @brief Insert a PDR into the TEID→PDR map (sorted by precedence). */
  void add_pfcp_ul_pdr_by_up_teid(
      const teid_t teid, std::shared_ptr<pfcp::pfcp_pdr>&);

  //------------------------------------------------------------------------------
  /** @brief Clean up a session and remove it from both hash maps. */
  void remove_pfcp_session(std::shared_ptr<pfcp::pfcp_session>&);

  //------------------------------------------------------------------------------
  /** @brief Generate a unique UP SEID for a new session. */
  uint64_t generate_seid() { return seid_generator_.get_uid(); }

  /** @brief Generate a unique N3 GTP-U TEID. */
  teid_t generate_teid_n3() { return teid_n3_generator__.get_uid(); }

  //------------------------------------------------------------------------------
  /** @brief Create tun interface(s), assign UE subnet addresses, start
   *  prThread_ / pwThread_. */
  void setup_pdn_interfaces();

  // ---- PDN I/O threads -----------------------------------------------------
  // moodycamel::ConcurrentQueue<pfcp::pfcp_session*> create_session_q;
  //------------------------------------------------------------------------------
  /** @brief DL worker thread — processes buffered packets from work_pool_. */
  void pdn_worker(
      const int id, const oai::utils::thread_sched_params& sched_params);

  //------------------------------------------------------------------------------
  /** @brief DL reader thread — reads IP packets from tun0 into free_pool_. */
  void pdn_read_loop(int sock_r, oai::utils::thread_sched_params sched_params);

  //------------------------------------------------------------------------------
  /** @brief Open an AF_PACKET/SOCK_DGRAM socket on @p ifname, optionally
   *  enabling promiscuous mode; returns fd or RETURNerror. */
  int create_pdn_socket(
      const char* const ifname, const bool promisc, int& if_index);
  /** @brief Open a raw IP socket bound to @p ifname; returns fd or
   *  RETURNerror. */
  int create_pdn_socket(const char* const ifname);
  /** @brief Open the Linux TUN device @p devname with @p flags; returns fd
   *  or RETURNerror. */
  int tun_open(char* devname, int flags);

  /** @brief One-shot post-construction initialisation (currently unused;
   *  setup_pdn_interfaces() is called directly from the constructor). */
  void setup();

 public:
  //------------------------------------------------------------------------------
  pfcp_switch();
  pfcp_switch(pfcp_switch const&) = delete;
  void operator=(pfcp_switch const&) = delete;
  ~pfcp_switch();

  //------------------------------------------------------------------------------
  /** @brief Insert a PDR into the UE-IP→PDR map (downlink). */
  void add_pfcp_dl_pdr_by_ue_ip(
      const uint32_t ue_ip, std::shared_ptr<pfcp::pfcp_pdr>&);

  //------------------------------------------------------------------------------
  /** @brief Allocate and return a new N3 F-TEID (3GPP TS 29.244 §8.2.3). */
  pfcp::fteid_t generate_fteid_n3();

  //------------------------------------------------------------------------------
  /** @brief Register a PDR for an uplink tunnel (ACCESS interface).
   *  @param pdr    The PDR to register.
   *  @param in     The allocated F-TEID.
   *  @param cause  Set to CAUSE_VALUE_REQUEST_ACCEPTED on success.
   *  @return true on success.
   */
  bool create_packet_in_access(
      std::shared_ptr<pfcp::pfcp_pdr>& pdr, const pfcp::fteid_t& in,
      uint8_t& cause);

  // ---- Per-packet look-up (data plane hot path) ----------------------------

  //------------------------------------------------------------------------------
  /** @brief Match and forward an uplink IPv4 packet from N3 (with TEID). */
  void pfcp_session_look_up_pack_in_access(
      struct iphdr* const iph, const std::size_t num_bytes,
      const endpoint& r_endpoint, const uint32_t tunnel_id);

  //------------------------------------------------------------------------------
  /** @brief Match and forward an uplink IPv6 packet from N3 (with TEID). */
  void pfcp_session_look_up_pack_in_access(
      struct ipv6hdr* const iph, const std::size_t num_bytes,
      const endpoint& r_endpoint, const uint32_t tunnel_id);

  //------------------------------------------------------------------------------
  /** @brief No-op overloads for raw-IP (no GTP) uplink path. */
  void pfcp_session_look_up_pack_in_access(
      struct iphdr* const iph, const std::size_t num_bytes,
      const endpoint& r_endpoint){};
  void pfcp_session_look_up_pack_in_access(
      struct ipv6hdr* const iph, const std::size_t num_bytes,
      const endpoint& r_endpoint){};

  //------------------------------------------------------------------------------
  /** @brief Match and forward a downlink packet read from tun0 (N6). */
  void pfcp_session_look_up_pack_in_core(
      const char* buffer, const std::size_t num_bytes);

  //------------------------------------------------------------------------------
  /** @brief Return false if the packet destination is a local UE subnet
   *         (avoids sending UE→UE traffic to the upstream default gateway). */
  bool no_internal_loop(struct iphdr* const iph, const std::size_t num_bytes);

  //------------------------------------------------------------------------------
  /** @brief Inject a packet into the PDN tun0 interface (N6 downlink). */
  void send_to_core(char* const ip_packet, const ssize_t len);

  // ---- N4 session event handlers -------------------------------------------

  /** @brief Variant type for the call_datapath() parameter. */
  using itti_n4_session_request = std::variant<
      itti_n4_session_establishment_request*,
      itti_n4_session_modification_request*, itti_n4_session_deletion_request*>;

  //------------------------------------------------------------------------------
  /** @brief Invoke a SessionManager CRUD function on the BPF datapath.
   *
   *  Exactly one of establishment_req / modification_request / deletion_req
   *  must be non-null.  The others must be nullptr.
   *
   *  @param establishment_request  Non-null for Session Establishment.
   *  @param modification_request   Non-null for Session Modification.
   *  @param deletion_req           Non-null for Session Deletion.
   *  @param s                      Active pfcp_session (snapshot copy).
   *  @param obj                    SessionManager instance.
   *  @param crud_func              Member function pointer to call.
   */
  void call_datapath(
      itti_n4_session_establishment_request* establishment_request,
      itti_n4_session_modification_request* modification_request,
      itti_n4_session_deletion_request* deletion_req, pfcp::pfcp_session* s,
      std::shared_ptr<SessionManager> obj,
      SessionOperationResult (SessionManager::*crud_func)(
          std::shared_ptr<pfcp::pfcp_session>,
          itti_n4_session_establishment_request*,
          itti_n4_session_modification_request*,
          itti_n4_session_deletion_request*));

  //------------------------------------------------------------------------------
  /** @brief Handle a PFCP Session Establishment Request (3GPP TS 29.244
   *  V17.10.0 §7.5.2). */
  void handle_pfcp_session_establishment_request(
      std::shared_ptr<itti_n4_session_establishment_request> sreq,
      itti_n4_session_establishment_response*);

  //------------------------------------------------------------------------------
  /** @brief Handle a PFCP Session Modification Request (3GPP TS 29.244
   *  V17.10.0 §7.5.4). */
  void handle_pfcp_session_modification_request(
      std::shared_ptr<itti_n4_session_modification_request> sreq,
      itti_n4_session_modification_response*);

  //------------------------------------------------------------------------------
  /** @brief Handle a PFCP Session Deletion Request (3GPP TS 29.244
   *  V17.10.0 §7.5.6). */
  void handle_pfcp_session_deletion_request(
      std::shared_ptr<itti_n4_session_deletion_request> sreq,
      itti_n4_session_deletion_response*);

  //------------------------------------------------------------------------------
  /** @brief ITTI timer callback — fires when the min-commit interval expires.
   */
  void time_out_min_commit_interval(const uint32_t timer_id);
  /** @brief ITTI timer callback — fires when the max-commit interval expires.
   */
  void time_out_max_commit_interval(const uint32_t timer_id);

  //------------------------------------------------------------------------------
  /** @brief Remove a session by its CP F-SEID (called by N4 deletion handler,
   *  3GPP TS 29.244 V17.10.0 §7.5.6). */
  void remove_pfcp_session(const pfcp::fseid_t& cp_fseid);
  /** @brief Remove the uplink TEID→PDR entry for the given TEID (§8.2.3). */
  void remove_pfcp_ul_pdrs_by_up_teid(const teid_t);
  /** @brief Remove the downlink UE-IP→PDR entry for the given UE IPv4
   *  address in host byte order (§8.2.62). */
  void remove_pfcp_dl_pdrs_by_ue_ip(const uint32_t);

  //------------------------------------------------------------------------------
  /** @brief Render all active sessions as formatted ASCII tables. */
  std::string to_string() const;
};
}  // namespace app
}  // namespace upf
}  // namespace oai
#endif  // FILE_PFCP_SWITCH_HPP_SEEN
