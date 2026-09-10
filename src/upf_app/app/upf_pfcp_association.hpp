/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_UPF_PFCP_ASSOCIATION_HPP_SEEN
#define FILE_UPF_PFCP_ASSOCIATION_HPP_SEEN

#include "3gpp_29.244.h"
#include "itti.hpp"

#include <mutex>
#include <unordered_map>
#include <vector>

namespace oai {
namespace upf {
namespace app {

#define PFCP_ASSOCIATION_HEARTBEAT_MAX_RETRIES 5
class pfcp_association {
 public:
  pfcp::node_id_t node_id;  // peer
  // A Node ID may be an FQDN, which cannot go in a sockaddr. Remember the
  // address the peer actually talks from, or anything we originate towards it
  // (heartbeats, Session Reports) has nowhere to go.
  struct in_addr peer_addr = {};
  bool has_peer_addr       = false;
  std::size_t hash_node_id;
  pfcp::recovery_time_stamp_t recovery_time_stamp;
  std::pair<bool, pfcp::cp_function_features_s> function_features;
  //
  mutable std::mutex m_sessions;
  std::set<pfcp::fseid_t> sessions;
  //
  timer_id_t timer_heartbeat;
  int num_retries_timer_heartbeat;
  uint64_t trxn_id_heartbeat;

  timer_id_t timer_association;

  explicit pfcp_association(const pfcp::node_id_t& node_id)
      : node_id(node_id),
        recovery_time_stamp(),
        function_features(),
        m_sessions(),
        sessions() {
    hash_node_id                = std::hash<pfcp::node_id_t>{}(node_id);
    timer_heartbeat             = ITTI_INVALID_TIMER_ID;
    num_retries_timer_heartbeat = 0;
    trxn_id_heartbeat           = 0;
  }
  pfcp_association(
      const pfcp::node_id_t& node_id,
      pfcp::recovery_time_stamp_t& recovery_time_stamp)
      : node_id(node_id),
        recovery_time_stamp(recovery_time_stamp),
        function_features(),
        m_sessions(),
        sessions() {
    hash_node_id                = std::hash<pfcp::node_id_t>{}(node_id);
    timer_heartbeat             = ITTI_INVALID_TIMER_ID;
    num_retries_timer_heartbeat = 0;
    trxn_id_heartbeat           = 0;
  }
  pfcp_association(
      const pfcp::node_id_t& ni, pfcp::recovery_time_stamp_t& rts,
      pfcp::cp_function_features_s& uff)
      : node_id(ni), recovery_time_stamp(rts), m_sessions(), sessions() {
    hash_node_id                = std::hash<pfcp::node_id_t>{}(node_id);
    function_features.first     = true;
    function_features.second    = uff;
    timer_heartbeat             = ITTI_INVALID_TIMER_ID;
    num_retries_timer_heartbeat = 0;
    trxn_id_heartbeat           = 0;
    timer_association           = {};
  }
  //     pfcp_association(pfcp_association const & p)
  //     {
  //       node_id = p.node_id;
  //       hash_node_id = p.hash_node_id;
  //       recovery_time_stamp = p.recovery_time_stamp;
  //       function_features = p.function_features;
  //       sessions = p.sessions;
  //       num_sessions = p.num_sessions;
  //       timer_heartbeat = p.timer_heartbeat;
  //       num_retries_timer_heartbeat = p.num_retries_timer_heartbeat;
  //       trxn_id_heartbeat = p.trxn_id_heartbeat;
  //     }
  void notify_add_session(const pfcp::fseid_t& cp_fseid);
  bool has_session(const pfcp::fseid_t& cp_fseid) const;
  void notify_del_session(const pfcp::fseid_t& cp_fseid);
  void del_sessions();
  void set(const pfcp::cp_function_features_s& ff) {
    function_features.first  = true;
    function_features.second = ff;
  };
  const pfcp::node_id_t& peer_node_id() const { return this->node_id; };
};

#define PFCP_MAX_ASSOCIATIONS 16

class pfcp_associations {
 private:
  std::vector<std::shared_ptr<pfcp_association>> pending_associations;
  /// Control-plane only: a few entries, never touched on the packet path.
  std::unordered_map<int32_t, std::shared_ptr<pfcp_association>> associations;
  mutable std::mutex associations_mutex;

  pfcp_associations() : associations(), pending_associations() {
    associations.reserve(PFCP_MAX_ASSOCIATIONS);
  };
  void trigger_heartbeat_request_procedure(
      std::shared_ptr<pfcp_association>& s);
  bool remove_peer_candidate_node(
      pfcp::node_id_t& node_id, std::shared_ptr<pfcp_association>& s);

 public:
  static pfcp_associations& get_instance() {
    static pfcp_associations instance;
    return instance;
  }

  pfcp_associations(pfcp_associations const&) = delete;
  void operator=(pfcp_associations const&) = delete;

  // Records where the peer talks from, so an FQDN Node ID is still reachable.
  void set_peer_addr(const pfcp::node_id_t& node_id, const endpoint& e);
  // Registers @p sa under @p node_id, replacing any previous association.
  void store_association(
      const pfcp::node_id_t& node_id, std::shared_ptr<pfcp_association>& sa);
  bool add_association(
      pfcp::node_id_t& node_id,
      pfcp::recovery_time_stamp_t& recovery_time_stamp);
  bool add_association(
      pfcp::node_id_t& node_id,
      pfcp::recovery_time_stamp_t& recovery_time_stamp,
      pfcp::cp_function_features_s& function_features);
  bool get_association(
      const pfcp::node_id_t& node_id,
      std::shared_ptr<pfcp_association>& sa) const;
  bool get_association(
      const pfcp::fseid_t& cp_fseid,
      std::shared_ptr<pfcp_association>& sa) const;

  void notify_add_session(
      const pfcp::node_id_t& node_id, const pfcp::fseid_t& cp_fseid);
  void notify_del_session(const pfcp::fseid_t& cp_fseid);

  bool add_peer_candidate_node(const pfcp::node_id_t& node_id);

  void restore_n4_sessions(const pfcp::node_id_t& node_id);

  void initiate_heartbeat_request(timer_id_t timer_id, uint64_t arg2_user);
  void timeout_heartbeat_request(timer_id_t timer_id, uint64_t arg2_user);

  void handle_receive_heartbeat_response(const uint64_t trxn_id);
};
}  // namespace app
}  // namespace upf
}  // namespace oai

#endif /* FILE_UPF_PFCP_ASSOCIATION_HPP_SEEN */
