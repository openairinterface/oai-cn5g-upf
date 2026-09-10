/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include <memory>
#include "common_defs.h"
#include "logger.hpp"
#include "pfcp_switch.hpp"
#include "upf_pfcp_association.hpp"
#include "upf_n4.hpp"

using namespace oai::upf::app;
// using namespace oai::config;
using namespace std;

extern itti_mw* itti_inst;
extern pfcp_switch* pfcp_switch_inst;
extern upf_n4* upf_n4_inst;

//------------------------------------------------------------------------------
void pfcp_association::notify_add_session(const pfcp::fseid_t& cp_fseid) {
  std::unique_lock<std::mutex> l(m_sessions);
  sessions.insert(cp_fseid);
}
//------------------------------------------------------------------------------
bool pfcp_association::has_session(const pfcp::fseid_t& cp_fseid) const {
  std::unique_lock<std::mutex> l(m_sessions);
  auto it = sessions.find(cp_fseid);
  if (it != sessions.end()) {
    return true;
  } else {
    return false;
  }
}
//------------------------------------------------------------------------------
void pfcp_association::notify_del_session(const pfcp::fseid_t& cp_fseid) {
  std::unique_lock<std::mutex> l(m_sessions);
  sessions.erase(cp_fseid);
}
//------------------------------------------------------------------------------
void pfcp_association::del_sessions() {
  std::unique_lock<std::mutex> l(m_sessions);
  for (std::set<pfcp::fseid_t>::iterator it = sessions.begin();
       it != sessions.end();) {
    pfcp_switch_inst->remove_pfcp_session(*it);
    sessions.erase(it++);
  }
}
//------------------------------------------------------------------------------
bool pfcp_associations::add_association(
    pfcp::node_id_t& node_id,
    pfcp::recovery_time_stamp_t& recovery_time_stamp) {
  std::shared_ptr<pfcp_association> sa = {};
  // The CP function may initiate the association itself, in which case there
  // is no pending candidate for it. Accept it anyway: we answer "request
  // accepted", so the association has to exist afterwards or everything that
  // looks a peer up later (Session Reports) silently finds nothing.
  if (!remove_peer_candidate_node(node_id, sa)) {
    sa = std::make_shared<pfcp_association>(node_id);
  }
  sa->recovery_time_stamp = recovery_time_stamp;
  sa->function_features   = {};
  store_association(node_id, sa);
  return true;
}
//------------------------------------------------------------------------------
bool pfcp_associations::add_association(
    pfcp::node_id_t& node_id, pfcp::recovery_time_stamp_t& recovery_time_stamp,
    pfcp::cp_function_features_s& function_features) {
  std::shared_ptr<pfcp_association> sa = {};
  if (!remove_peer_candidate_node(node_id, sa)) {
    sa = std::make_shared<pfcp_association>(node_id);
  }
  sa->recovery_time_stamp = recovery_time_stamp;
  sa->set(function_features);
  store_association(node_id, sa);
  return true;
}

//------------------------------------------------------------------------------
void pfcp_associations::store_association(
    const pfcp::node_id_t& node_id, std::shared_ptr<pfcp_association>& sa) {
  std::size_t hash_node_id = std::hash<pfcp::node_id_t>{}(node_id);
  {
    std::lock_guard<std::mutex> lk(associations_mutex);
    associations[(int32_t) hash_node_id] = sa;
  }
  // Only heartbeat a peer we started the association with. Answering the CP's
  // heartbeats is enough the other way round: an SMF that also receives
  // requests on that socket discards them as untriggered messages and then
  // tears the association down.
  if (node_id.node_id_type == pfcp::NODE_ID_TYPE_IPV4_ADDRESS) {
    trigger_heartbeat_request_procedure(sa);
  }
  Logger::upf_n4().info(
      "Associated with CP function %s", node_id.toString().c_str());
}
//------------------------------------------------------------------------------
void pfcp_associations::set_peer_addr(
    const pfcp::node_id_t& node_id, const endpoint& e) {
  if (e.family() != AF_INET) return;
  std::shared_ptr<pfcp_association> sa = {};
  if (!get_association(node_id, sa) || !sa) return;
  sa->peer_addr =
      reinterpret_cast<const struct sockaddr_in*>(&e.addr_storage)->sin_addr;
  sa->has_peer_addr = true;
}
//------------------------------------------------------------------------------
bool pfcp_associations::get_association(
    const pfcp::node_id_t& node_id,
    std::shared_ptr<pfcp_association>& sa) const {
  std::size_t hash_node_id = std::hash<pfcp::node_id_t>{}(node_id);
  std::lock_guard<std::mutex> lk(associations_mutex);
  auto pit = associations.find((int32_t) hash_node_id);
  if (pit != associations.end()) {
    sa = pit->second;
    return true;
  }
  return false;
}
//------------------------------------------------------------------------------
bool pfcp_associations::get_association(
    const pfcp::fseid_t& cp_fseid,
    std::shared_ptr<pfcp_association>& sa) const {
  std::lock_guard<std::mutex> lk(associations_mutex);
  for (const auto& entry : associations) {
    if (entry.second->has_session(cp_fseid)) {
      sa = entry.second;
      return true;
    }
  }
  return false;
}
//------------------------------------------------------------------------------
bool pfcp_associations::remove_peer_candidate_node(
    pfcp::node_id_t& node_id, std::shared_ptr<pfcp_association>& s) {
  for (std::vector<std::shared_ptr<pfcp_association>>::iterator it =
           pending_associations.begin();
       it < pending_associations.end(); ++it) {
    if ((*it)->node_id == node_id) {
      s = *it;
      pending_associations.erase(it);
      return true;
    }
  }
  return false;
}
//------------------------------------------------------------------------------
bool pfcp_associations::add_peer_candidate_node(
    const pfcp::node_id_t& node_id) {
  for (std::vector<std::shared_ptr<pfcp_association>>::iterator it =
           pending_associations.begin();
       it < pending_associations.end(); ++it) {
    if ((*it)->node_id == node_id) {
      // TODO purge sessions of this node
      Logger::upf_n4().info("TODO purge sessions of this node");
      pending_associations.erase(it);
      break;
    }
  }
  pfcp_association* association = new pfcp_association(node_id);
  std::shared_ptr<pfcp_association> s =
      std::shared_ptr<pfcp_association>(association);
  pending_associations.push_back(s);
  return true;
  // start_timer = itti_inst->timer_setup(0,0, TASK_UPF_N4,
  // TASK_MME_S11_TIMEOUT_SEND_GTPU_PING, 0);
}
//------------------------------------------------------------------------------
void pfcp_associations::trigger_heartbeat_request_procedure(
    std::shared_ptr<pfcp_association>& s) {
  s->timer_heartbeat = itti_inst->timer_setup(
      5, 0, TASK_UPF_N4, TASK_UPF_N4_TRIGGER_HEARTBEAT_REQUEST,
      s->hash_node_id);
}
//------------------------------------------------------------------------------
void pfcp_associations::initiate_heartbeat_request(
    timer_id_t timer_id, uint64_t arg2_user) {
  size_t hash = (size_t) arg2_user;
  for (auto it : associations) {
    if (it.second->hash_node_id == hash) {
      Logger::upf_n4().info("PFCP HEARTBEAT PROCEDURE hash %u starting", hash);
      it.second->num_retries_timer_heartbeat = 0;
      upf_n4_inst->send_heartbeat_request(it.second);
    }
  }
}
//------------------------------------------------------------------------------
void pfcp_associations::timeout_heartbeat_request(
    timer_id_t timer_id, uint64_t arg2_user) {
  size_t hash = (size_t) arg2_user;
  for (auto it : associations) {
    if (it.second->hash_node_id == hash) {
      Logger::upf_n4().info("PFCP HEARTBEAT PROCEDURE hash %u TIMED OUT", hash);
      if (it.second->num_retries_timer_heartbeat <
          PFCP_ASSOCIATION_HEARTBEAT_MAX_RETRIES) {
        it.second->num_retries_timer_heartbeat++;
        upf_n4_inst->send_heartbeat_request(it.second);
      } else {
        it.second->del_sessions();
        pfcp::node_id_t node_id  = it.second->node_id;
        std::size_t hash_node_id = it.second->hash_node_id;
        associations.erase((uint32_t) hash_node_id);
        add_peer_candidate_node(node_id);
        break;
      }
    }
  }
}
//------------------------------------------------------------------------------
void pfcp_associations::handle_receive_heartbeat_response(
    const uint64_t trxn_id) {
  for (auto it : associations) {
    if (it.second->trxn_id_heartbeat == trxn_id) {
      itti_inst->timer_remove(it.second->timer_heartbeat);
      trigger_heartbeat_request_procedure(it.second);
      return;
    }
  }
  Logger::upf_n4().info(
      "PFCP HEARTBEAT PROCEDURE trxn_id %d NOT FOUND", trxn_id);
}

//------------------------------------------------------------------------------
void pfcp_associations::notify_add_session(
    const pfcp::node_id_t& node_id, const pfcp::fseid_t& cp_fseid) {
  std::shared_ptr<pfcp_association> sa = {};
  if (get_association(node_id, sa)) {
    sa->notify_add_session(cp_fseid);
    Logger::upf_app().debug(
        "Session registered with association %s: cp_fseid seid=0x%lx v4=%u "
        "addr=0x%x",
        node_id.toString().c_str(), cp_fseid.seid, cp_fseid.v4,
        cp_fseid.ipv4_address.s_addr);
  } else {
    // Silence here is why a Session Report later cannot find its association:
    // the report path looks the session up by cp_fseid, and nothing ever
    // recorded it.
    Logger::upf_app().warn(
        "Session NOT registered: no association for node %s. Session Reports "
        "for cp_fseid seid=0x%lx will not be sent.",
        node_id.toString().c_str(), cp_fseid.seid);
  }
}
//------------------------------------------------------------------------------
void pfcp_associations::notify_del_session(const pfcp::fseid_t& cp_fseid) {
  std::shared_ptr<pfcp_association> sa = {};
  if (get_association(cp_fseid, sa)) {
    sa->notify_del_session(cp_fseid);
  }
}
