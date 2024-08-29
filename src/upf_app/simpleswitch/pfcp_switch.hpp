/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

/*! \file pfcp_switch.hpp
   \author  Lionel GAUTHIER
   \date 2019
   \email: lionel.gauthier@eurecom.fr
*/

#ifndef FILE_PFCP_SWITCH_HPP_SEEN
#define FILE_PFCP_SWITCH_HPP_SEEN

//#include "concurrentqueue.h"
#include "itti.hpp"
#include "itti_msg_n4.hpp"
#include "msg_pfcp.hpp"
#include "pfcp_session.hpp"
#include "uint_generator.hpp"
#include "thread_sched.hpp"

#include <folly/AtomicHashMap.h>
#include <folly/MPMCQueue.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <unordered_map>
#include <memory>
#include <netinet/in.h>
#include <thread>
#include <vector>

#include <SessionManager.h>
#include <variant>

#include <pthread.h>

namespace oai {
namespace upf {
namespace app {

// Have to be tuned for sdt situations
#define PFCP_SWITCH_MAX_SESSIONS 1024
#define PFCP_SWITCH_MAX_PDRS 1024

typedef struct iovec_q_item_s {
  struct iovec msg_iov;
  struct msghdr msg;
} iovec_q_item_t;

class pfcp_switch {
 private:
  // Very unoptimized
#define PFCP_SWITCH_RECV_BUFFER_SIZE 2048
#define ROOM_FOR_GTPV1U_G_PDU 64
  folly::MPMCQueue<iovec_q_item_t*>* free_pool_;
  folly::MPMCQueue<iovec_q_item_t*>* work_pool_;
  uint32_t num_threads_;
  char* recv_buffer_alloc_;
  char recv_buffer_[PFCP_SWITCH_RECV_BUFFER_SIZE];
  std::thread pwThread_;
  std::thread prThread_;
  pthread_t prThreadToCancel;
  int* socks_r_ptr;
  int sock_w;
  bool terminatePW_;
  // std::string                               gw_mac_address;
  int pdn_if_index;

  oai::utils::uint_generator<uint64_t> seid_generator_;
  oai::utils::uint_generator<teid_t> teid_n3_generator__;

#define TASK_UPF_PFCP_SWITCH_MAX_COMMIT_INTERVAL (0)
#define TASK_UPF_PFCP_SWITCH_MIN_COMMIT_INTERVAL (1)

#define PFCP_SWITCH_MAX_COMMIT_INTERVAL_MILLISECONDS 200
#define PFCP_SWITCH_MIN_COMMIT_INTERVAL_MILLISECONDS 50

  // switching_data_per_cpu_socket             switching_data[];
  std::unordered_map<pfcp::fseid_t, std::shared_ptr<pfcp::pfcp_session>>
      cp_fseid2pfcp_sessions;
  folly::AtomicHashMap<uint64_t, std::shared_ptr<pfcp::pfcp_session>>
      up_seid2pfcp_sessions;
  folly::AtomicHashMap<
      teid_t, std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>>
      ul_n3_teid2pfcp_pdr;
  folly::AtomicHashMap<
      uint32_t, std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>>
      ue_ipv4_hbo2pfcp_pdr;

  // moodycamel::ConcurrentQueue<pfcp::pfcp_session*> create_session_q;

  void pdn_worker(const int id, const util::thread_sched_params& sched_params);
  void pdn_read_loop(int sock_r, util::thread_sched_params sched_params);
  int create_pdn_socket(
      const char* const ifname, const bool promisc, int& if_index);
  int create_pdn_socket(const char* const ifname);
  int tun_open(char* devname, int flags);
  void setup_pdn_interfaces();

  timer_id_t timer_max_commit_interval_id;
  timer_id_t timer_min_commit_interval_id;

  void stop_timer_min_commit_interval();
  void start_timer_min_commit_interval();
  void stop_timer_max_commit_interval();
  void start_timer_max_commit_interval();

  void commit_changes();

  bool get_pfcp_session_by_cp_fseid(
      const pfcp::fseid_t&, std::shared_ptr<pfcp::pfcp_session>&) const;
  bool get_pfcp_session_by_up_seid(
      const uint64_t, std::shared_ptr<pfcp::pfcp_session>&) const;
  bool get_pfcp_ul_pdrs_by_up_teid(
      const teid_t,
      std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>&) const;
  bool get_pfcp_dl_pdrs_by_ue_ip(
      const uint32_t,
      std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>&) const;

  void add_pfcp_session_by_cp_fseid(
      const pfcp::fseid_t&, std::shared_ptr<pfcp::pfcp_session>&);
  void add_pfcp_session_by_up_seid(
      const uint64_t, std::shared_ptr<pfcp::pfcp_session>&);
  void add_pfcp_ul_pdr_by_up_teid(
      const teid_t teid, std::shared_ptr<pfcp::pfcp_pdr>&);

  void remove_pfcp_session(std::shared_ptr<pfcp::pfcp_session>&);

  uint64_t generate_seid() { return seid_generator_.get_uid(); };

  teid_t generate_teid_n3() { return teid_n3_generator__.get_uid(); };

  void setup();

 public:
  pfcp_switch();
  pfcp_switch(pfcp_switch const&) = delete;
  void operator=(pfcp_switch const&) = delete;
  ~pfcp_switch();

  void add_pfcp_dl_pdr_by_ue_ip(
      const uint32_t ue_ip, std::shared_ptr<pfcp::pfcp_pdr>&);

  pfcp::fteid_t generate_fteid_n3();
  bool create_packet_in_access(
      std::shared_ptr<pfcp::pfcp_pdr>& pdr, const pfcp::fteid_t& in,
      uint8_t& cause);

  void pfcp_session_look_up_pack_in_access(
      struct iphdr* const iph, const std::size_t num_bytes,
      const endpoint& r_endpoint, const uint32_t tunnel_id);
  void pfcp_session_look_up_pack_in_access(
      struct ipv6hdr* const iph, const std::size_t num_bytes,
      const endpoint& r_endpoint, const uint32_t tunnel_id);
  void pfcp_session_look_up_pack_in_access(
      struct iphdr* const iph, const std::size_t num_bytes,
      const endpoint& r_endpoint){};
  void pfcp_session_look_up_pack_in_access(
      struct ipv6hdr* const iph, const std::size_t num_bytes,
      const endpoint& r_endpoint){};
  // void pfcp_session_look_up(struct ethhdr* const ethh, const std::size_t
  // num_bytes);

  void pfcp_session_look_up_pack_in_core(
      const char* buffer, const std::size_t num_bytes);

  bool no_internal_loop(struct iphdr* const iph, const std::size_t num_bytes);
  void send_to_core(char* const ip_packet, const ssize_t len);

  using itti_n4_session_request = std::variant<
      itti_n4_session_establishment_request*,
      itti_n4_session_modification_request*, itti_n4_session_deletion_request*>;

  void call_datapath(
      itti_n4_session_establishment_request* establishment_req,
      itti_n4_session_modification_request* modification_request,
      itti_n4_session_deletion_request* deletion_req, pfcp::pfcp_session* s,
      std::shared_ptr<SessionManager> obj,
      void (SessionManager::*crud_func)(
          std::shared_ptr<pfcp::pfcp_session>,
          itti_n4_session_establishment_request* est_req,
          itti_n4_session_modification_request* mod_req,
          itti_n4_session_deletion_request* del_req));

  void handle_pfcp_session_establishment_request(
      std::shared_ptr<itti_n4_session_establishment_request> sreq,
      itti_n4_session_establishment_response*);
  void handle_pfcp_session_modification_request(
      std::shared_ptr<itti_n4_session_modification_request> sreq,
      itti_n4_session_modification_response*);
  void handle_pfcp_session_deletion_request(
      std::shared_ptr<itti_n4_session_deletion_request> sreq,
      itti_n4_session_deletion_response*);

  void time_out_min_commit_interval(const uint32_t timer_id);
  void time_out_max_commit_interval(const uint32_t timer_id);

  void remove_pfcp_session(const pfcp::fseid_t& cp_fseid);
  void remove_pfcp_ul_pdrs_by_up_teid(const teid_t);
  void remove_pfcp_dl_pdrs_by_ue_ip(const uint32_t);

  std::string to_string() const;
};
}  // namespace app
}  // namespace upf
}  // namespace oai
#endif /* FILE_PFCP_SWITCH_HPP_SEEN */
