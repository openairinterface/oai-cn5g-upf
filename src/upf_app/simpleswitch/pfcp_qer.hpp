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
  std::pair<bool, pfcp::qer_id_t> qer_id;
  std::pair<bool, pfcp::qer_correlation_id_t> qer_correlation_id;
  std::pair<bool, pfcp::gate_status_t> gate_status;
  std::pair<bool, pfcp::mbr_t> maximum_bitrate;
  std::pair<bool, pfcp::gbr_t> guaranteed_bitrate;
  std::pair<bool, pfcp::qfi_t> qos_flow_id;
  std::pair<bool, pfcp::rqi_t> reflective_qos;
  std::pair<bool, pfcp::paging_policy_indicator_t> paging_policy_indicator;
  std::pair<bool, pfcp::averaging_window_t> averaging_window;

  /*
   * Not considered for N4 interface:
   *    std::pair<bool, pfcp::packet_rate_t> packet_rate;
   *    pfcp::dl_flow_level_marking_t dl_flow_level_marking;
   *
   */
  //------------------------------------------------------------------------------
  pfcp_qer()
      : qer_id(),
        qer_correlation_id(),
        gate_status(),
        maximum_bitrate(),
        guaranteed_bitrate(),
        qos_flow_id(),
        reflective_qos(),
        paging_policy_indicator(),
        averaging_window() {}

  //------------------------------------------------------------------------------
  explicit pfcp_qer(const pfcp::create_qer& c)
      : qer_id(c.qer_id),
        qer_correlation_id(c.qer_correlation_id),
        gate_status(c.gate_status),
        maximum_bitrate(c.maximum_bitrate),
        guaranteed_bitrate(c.guaranteed_bitrate),
        qos_flow_id(c.qos_flow_identifier),
        reflective_qos(c.reflective_qos),
        paging_policy_indicator(c.paging_policy_indicator),
        averaging_window(c.averaging_window) {}

  //------------------------------------------------------------------------------
  pfcp_qer(const pfcp_qer& c)
      : qer_id(c.qer_id),
        qer_correlation_id(c.qer_correlation_id),
        gate_status(c.gate_status),
        maximum_bitrate(c.maximum_bitrate),
        guaranteed_bitrate(c.guaranteed_bitrate),
        qos_flow_id(c.qos_flow_id),
        reflective_qos(c.reflective_qos),
        paging_policy_indicator(c.paging_policy_indicator),
        averaging_window(c.averaging_window) {}

  //------------------------------------------------------------------------------
  // virtual ~pfcp_qer() {};

  //------------------------------------------------------------------------------
  void set(const pfcp::qer_id_t& v) {
    qer_id.first  = true;
    qer_id.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::qer_correlation_id_t& v) {
    qer_correlation_id.first  = true;
    qer_correlation_id.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::gate_status_t& v) {
    gate_status.first  = true;
    gate_status.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::mbr_t& v) {
    maximum_bitrate.first  = true;
    maximum_bitrate.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::gbr_t& v) {
    guaranteed_bitrate.first  = true;
    guaranteed_bitrate.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::qfi_t& v) {
    qos_flow_id.first  = true;
    qos_flow_id.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::rqi_t& v) {
    reflective_qos.first  = true;
    reflective_qos.second = v;
  }

  //------------------------------------------------------------------------------

  void set(const pfcp::paging_policy_indicator_t& v) {
    paging_policy_indicator.first  = true;
    paging_policy_indicator.second = v;
  }

  //------------------------------------------------------------------------------

  void set(const pfcp::averaging_window_t& v) {
    averaging_window.first  = true;
    averaging_window.second = v;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::qer_id_t& v) const {
    if (qer_id.first) {
      v = qer_id.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::gate_status_t& v) const {
    if (gate_status.first) {
      v = gate_status.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::qer_correlation_id_t& v) const {
    if (qer_correlation_id.first) {
      v = qer_correlation_id.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::mbr_t& v) const {
    if (maximum_bitrate.first) {
      v = maximum_bitrate.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::gbr_t& v) const {
    if (guaranteed_bitrate.first) {
      v = guaranteed_bitrate.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::qfi_t& v) const {
    if (qos_flow_id.first) {
      v = qos_flow_id.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::rqi_t& v) const {
    if (reflective_qos.first) {
      v = reflective_qos.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::paging_policy_indicator_t& v) const {
    if (paging_policy_indicator.first) {
      v = paging_policy_indicator.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------

  bool get(pfcp::averaging_window_t& v) const {
    if (averaging_window.first) {
      v = averaging_window.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool update(const pfcp::update_qer& update, uint8_t& cause_value);
};
}  // namespace pfcp

#endif
