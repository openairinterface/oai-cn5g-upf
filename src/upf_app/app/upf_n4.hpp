/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_SGWU_SX_HPP_SEEN
#define FILE_SGWU_SX_HPP_SEEN

#include "endpoint.hpp"
#include "pfcp.hpp"
#include "itti_msg_n4.hpp"
#include "msg_pfcp.hpp"
#include "upf_pfcp_association.hpp"

#include <map>
#include <mutex>
#include <optional>
#include <thread>
#include <utility>

namespace oai {
namespace upf {
namespace app {

#define TASK_UPF_N4_TRIGGER_HEARTBEAT_REQUEST (0)
#define TASK_UPF_N4_TIMEOUT_HEARTBEAT_REQUEST (1)
#define TASK_UPF_N4_TIMEOUT_ASSOCIATION_REQUEST (2)

static_assert(
    PFCP_TIMER_ARG1_MSG_RETRY != PFCP_TIMER_ARG1_PROC_CLEANUP &&
        PFCP_TIMER_ARG1_MSG_RETRY != TASK_UPF_N4_TRIGGER_HEARTBEAT_REQUEST &&
        PFCP_TIMER_ARG1_MSG_RETRY != TASK_UPF_N4_TIMEOUT_HEARTBEAT_REQUEST &&
        PFCP_TIMER_ARG1_MSG_RETRY != TASK_UPF_N4_TIMEOUT_ASSOCIATION_REQUEST &&
        PFCP_TIMER_ARG1_PROC_CLEANUP != TASK_UPF_N4_TRIGGER_HEARTBEAT_REQUEST &&
        PFCP_TIMER_ARG1_PROC_CLEANUP != TASK_UPF_N4_TIMEOUT_HEARTBEAT_REQUEST &&
        PFCP_TIMER_ARG1_PROC_CLEANUP != TASK_UPF_N4_TIMEOUT_ASSOCIATION_REQUEST,
    "an arg1_user value is claimed by both a TASK_UPF_N4 trigger and the PFCP "
    "transaction layer; upf_n4_task()'s TIME_OUT dispatch cannot tell them "
    "apart and one handler becomes dead code");

class upf_n4 : public pfcp::pfcp_l4_stack {
 private:
  std::thread::id thread_id;
  std::thread thread;

  uint64_t recovery_time_stamp;  // timestamp in seconds
  pfcp::up_function_features_s up_function_features;
  pfcp::enterprise_specific_s enterprise_specific;

  void start_association(const pfcp::node_id_t& node_id);

  // The Downlink Data Reports still waiting for their response: trxn_id ->
  // (up_seid, pdr_id). Filled on TASK_UPF_N4 before the send, emptied by the
  // response (receive thread) or by the give-up (TASK_UPF_N4). dldr_mutex_ is
  // a leaf lock, never held together with trx_mutex_.
  std::mutex dldr_mutex_;
  std::map<uint64_t, std::pair<uint64_t, uint16_t>> dldr_trxn_;

 protected:
  // When a DL Data Report is given up on, asks TASK_UPF_APP to re-arm the
  // PDR's notification latch. Overrides pfcp_l4_stack's.
  void notify_ul_error(
      const pfcp::pfcp_procedure& p, const ::cause_value_e cause) override;

 public:
  upf_n4();
  upf_n4(upf_n4 const&)         = delete;
  void operator=(upf_n4 const&) = delete;

  void handle_itti_msg(itti_n4_heartbeat_request& s) {};
  void handle_itti_msg(itti_n4_heartbeat_response& s) {};
  void handle_itti_msg(itti_n4_association_setup_request& s) {};
  void handle_itti_msg(itti_n4_association_setup_response& s) {};
  void handle_itti_msg(itti_n4_association_update_request& s) {};
  void handle_itti_msg(itti_n4_association_update_response& s) {};
  void handle_itti_msg(itti_n4_association_release_request& s) {};
  void handle_itti_msg(itti_n4_association_release_response& s) {};
  void handle_itti_msg(itti_n4_version_not_supported_response& s) {};
  void handle_itti_msg(itti_n4_node_report_response& s) {};
  void handle_itti_msg(itti_n4_session_set_deletion_request& s) {};
  void handle_itti_msg(itti_n4_session_establishment_response& s);
  void handle_itti_msg(itti_n4_session_modification_response& s);
  void handle_itti_msg(itti_n4_session_deletion_response& s);
  void handle_itti_msg(itti_n4_session_report_request& s);
  void handle_itti_msg(itti_n4_session_report_response& s) {};

  void send_n4_msg(itti_n4_heartbeat_request& s) {};
  void send_n4_msg(itti_n4_heartbeat_response& s) {};
  void send_n4_msg(itti_n4_association_setup_request& s);
  void send_n4_msg(itti_n4_association_setup_response& s);
  void send_n4_msg(itti_n4_association_update_request& s) {};
  void send_n4_msg(itti_n4_association_update_response& s) {};
  void send_n4_msg(itti_n4_association_release_request& s) {};
  void send_n4_msg(itti_n4_association_release_response& s) {};
  void send_n4_msg(itti_n4_version_not_supported_response& s) {};
  void send_n4_msg(itti_n4_node_report_request& s) {};
  void send_n4_msg(itti_n4_session_set_deletion_response& s) {};
  void send_n4_msg(itti_n4_session_establishment_response& s);
  void send_n4_msg(itti_n4_session_modification_response& s);
  void send_n4_msg(itti_n4_session_deletion_response& s);
  void send_n4_msg(itti_n4_session_report_request& s);

  // Hands the report to TASK_UPF_N4, which alone calls send_request().
  // Returns false when the enqueue is refused (see
  // enqueue_session_report_request()). dldr is (up_seid, pdr_id) for a
  // Downlink Data Report, empty otherwise.
  bool send_n4_msg(
      const pfcp::fseid_t& cp_fseid, const pfcp::pfcp_session_report_request& s,
      std::optional<std::pair<uint64_t, uint16_t>> dldr = std::nullopt);

  static bool enqueue_session_report_request(
      const pfcp::fseid_t& cp_fseid, const pfcp::pfcp_session_report_request& s,
      bool& association_found,
      std::optional<std::pair<uint64_t, uint16_t>> dldr = std::nullopt);

  void send_heartbeat_request(std::shared_ptr<pfcp_association>& a);
  void send_heartbeat_response(
      const endpoint& r_endpoint, const uint64_t trxn_id);

  void handle_receive_pfcp_msg(
      pfcp::pfcp_msg& msg, const endpoint& remote_endpoint);
  void handle_receive(
      char* recv_buffer, const std::size_t bytes_transferred,
      const endpoint& remote_endpoint) override;
  // node related
  void handle_receive_heartbeat_request(
      pfcp::pfcp_msg& msg, const endpoint& remote_endpoint);
  void handle_receive_heartbeat_response(
      pfcp::pfcp_msg& msg, const endpoint& remote_endpoint);
  void handle_receive_association_setup_response(
      pfcp::pfcp_msg& msg, const endpoint& remote_endpoint);
  void handle_receive_association_setup_request(
      pfcp::pfcp_msg& msg, const endpoint& remote_endpoint);
  // session related
  void handle_receive_session_establishment_request(
      pfcp::pfcp_msg& msg, const endpoint& remote_endpoint);
  void handle_receive_session_modification_request(
      pfcp::pfcp_msg& msg, const endpoint& remote_endpoint);
  void handle_receive_session_deletion_request(
      pfcp::pfcp_msg& msg, const endpoint& remote_endpoint);
  void handle_receive_session_report_response(
      pfcp::pfcp_msg& msg, const endpoint& remote_endpoint);

  void time_out_itti_event(const uint32_t timer_id);
};
}  // namespace app
}  // namespace upf
}  // namespace oai
#endif /* FILE_SGWU_SX_HPP_SEEN */
