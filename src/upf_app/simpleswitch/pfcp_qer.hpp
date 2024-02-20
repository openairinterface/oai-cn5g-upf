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

/*! \file pfcp_qer.hpp
   \author  Franck MESSAOUDI
   \date 2024
   \email: franck.messaoudi@openairinterface.org
*/

#ifndef FILE_PFCP_QER_HPP_SEEN
#define FILE_PFCP_QER_HPP_SEEN

#include <linux/ip.h>
#include <linux/ipv6.h>
#include "msg_pfcp.hpp"

namespace pfcp {

class pfcp_qer {
 public:
  pfcp::qer_id_t qer_id;
  pfcp::qer_correlation_id_t qer_correlation_id;
  pfcp::gate_status_t gate_status;
  std::pair<bool, pfcp::mbr_t> mbr;
  std::pair<bool, pfcp::gbr_t> gbr;
  std::pair<bool, pfcp::packet_rate_t> packet_rate;
  //std::pair<bool, pfcp::packet_rate_statues> packet_rate_status; ///?
  pfcp::dl_flow_level_marking_t dl_flow_level_marking;
  pfcp::qfi_t qfi;
  pfcp::rqi_t rqi;
  pfcp::paging_policy_indicator_t paging_policy_indicator;
  pfcp::averaging_window_t averaging_window;
  //pfcp::qer_control_indication_t qer_control_indication;/// ? 


//------------------------------------------------------------------------------  
  pfcp_qer()
      : qer_id(),
        qer_correlation_id(),
        gate_status(),
        mbr(),
        gbr(),
        packet_rate(),
        //packet_rate_status(), 
        dl_flow_level_marking(),
        qfi(),
        rqi(),
        paging_policy_indicator(),
        averaging_window()
        //qer_control_indication(),
        {}


//------------------------------------------------------------------------------
  explicit pfcp_qer(const pfcp::create_qer& c)
      : qer_id(c.qer_id.second),
        qer_correlation_id(c.qer_correlation_id),
        gate_status(c.gate_status),
        mbr(c.maximum_bitrate),
        gbr(c.guaranteed_bitrate),
        packet_rate(c.packet_rate),
        //packet_rate_status(c.packet_rate_status), 
        dl_flow_level_marking(c.dl_flow_level_marking),
        qfi(c.qos_flow_identifier),
        rqi(c.reflective_qos),
        //paging_policy_indicator(c.),
        //averaging_window(c.)
        //qer_control_indication(),
  }


//------------------------------------------------------------------------------
  pfcp_far(const pfcp_far& c)
      : far_id(c.far_id),
        apply_action(c.apply_action),
        forwarding_parameters(c.forwarding_parameters),
        duplicating_parameters(c.duplicating_parameters),
        bar_id(c.bar_id) {}

  // virtual ~pfcp_far() {};
  void set(const pfcp::far_id_t& v) { far_id = v; }
  void set(const pfcp::apply_action_t& v) { apply_action = v; }
  void set(const pfcp::forwarding_parameters& v) {
    forwarding_parameters.first  = true;
    forwarding_parameters.second = v;
  }
  void set(const pfcp::duplicating_parameters& v) {
    duplicating_parameters.first  = true;
    duplicating_parameters.second = v;
  }
  void set(const pfcp::bar_id_t& v) {
    bar_id.first  = true;
    bar_id.second = v;
  }

  bool get(pfcp::far_id_t& v) const {
    v = far_id;
    return true;
  }
  bool get(pfcp::apply_action_t& v) const {
    v = apply_action;
    return true;
  }
  bool get(pfcp::forwarding_parameters& v) const {
    if (forwarding_parameters.first) {
      v = forwarding_parameters.second;
      return true;
    }
    return false;
  }
  bool get(pfcp::duplicating_parameters& v) const {
    if (duplicating_parameters.first) {
      v = duplicating_parameters.second;
      return true;
    }
    return false;
  }
  bool get(pfcp::bar_id_t& v) const {
    if (bar_id.first) {
      v = bar_id.second;
      return true;
    }
    return false;
  }

  bool update(const pfcp::update_far& update, uint8_t& cause_value);

  void apply_forwarding_rules(
      struct iphdr* const iph, const std::size_t num_bytes, bool& nocp,
      bool& buff, uint8_t qfi);
};
}  // namespace pfcp

#endif
