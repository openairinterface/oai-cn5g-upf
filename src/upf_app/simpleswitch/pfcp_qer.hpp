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
  std::pair<bool, pfcp::mbr_t> mbr;
  std::pair<bool, pfcp::gbr_t> gbr;
  std::pair<bool, pfcp::qfi_t> qfi;
  std::pair<bool, pfcp::rqi_t> rqi;
  std::pair<bool, pfcp::paging_policy_indicator_t> paging_policy_indicator;

  /*
   * Not considered for N4 interface:
   *    std::pair<bool, pfcp::packet_rate_t> packet_rate;
   *    pfcp::dl_flow_level_marking_t dl_flow_level_marking;
   *
   */

  /*
   * Types Not Implemented:
   *   pfcp::qer_control_indication_t qer_control_indication;
   *   std::pair<bool, pfcp::packet_rate_status> packet_rate_status; ///?
   */

  /*
   * Optional Parameters:
   *   std::pair<bool, pfcp::averaging_window_t> averaging_window;
   */
  //------------------------------------------------------------------------------
  pfcp_qer()
      : qer_id(),
        qer_correlation_id(),
        gate_status(),
        mbr(),
        gbr(),
        qfi(),
        rqi(),
        paging_policy_indicator() {}
  /*
   * packet_rate(),
   * dl_flow_level_marking(),
   * packet_rate_status(),
   * qer_control_indication(),
   * averaging_window()
   */

  //------------------------------------------------------------------------------
  explicit pfcp_qer(const pfcp::create_qer& c)
      : qer_id(c.qer_id),
        qer_correlation_id(c.qer_correlation_id),
        gate_status(c.gate_status),
        mbr(c.maximum_bitrate),
        gbr(c.guaranteed_bitrate),
        qfi(c.qos_flow_identifier),
        rqi(c.reflective_qos) {}
  /*
   * paging_policy_indicator(c.?),
   * packet_rate(c.packet_rate),
   * dl_flow_level_marking(c.dl_flow_level_marking),
   * packet_rate_status(c.packet_rate_status),
   * qer_control_indication(),
   * averaging_window(c.?)
   */

  //------------------------------------------------------------------------------
  pfcp_qer(const pfcp_qer& c)
      : qer_id(c.qer_id),
        qer_correlation_id(c.qer_correlation_id),
        gate_status(c.gate_status),
        mbr(c.mbr),
        gbr(c.gbr),
        qfi(c.qfi),
        rqi(c.rqi) {}
  /*
   * paging_policy_indicator(c.?),
   * packet_rate(c.packet_rate),
   * dl_flow_level_marking(c.dl_flow_level_marking),
   * packet_rate_status(c.packet_rate_status),
   * qer_control_indication(),
   * averaging_window(c.?)
   */

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
    mbr.first  = true;
    mbr.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::gbr_t& v) {
    gbr.first  = true;
    gbr.second = v;
  }

  //------------------------------------------------------------------------------
  /*
   * void set(const pfcp::packet_rate_t& v) {
   *  packet_rate.first  = true;
   *  packet_rate.second = v;
   * }
   */

  //------------------------------------------------------------------------------
  /*
   * void set(const pfcp::packet_rate_status_t& v) {
   *   packet_rate_status.first  = true;
   *   packet_rate_status.second = v;
   * }
   */

  //------------------------------------------------------------------------------
  /*
   * void set(const pfcp::dl_flow_level_marking_t& v) {
   *   dl_flow_level_marking.first = true;
   *   dl_flow_level_marking.second = v;
   * }
   */

  //------------------------------------------------------------------------------
  void set(const pfcp::qfi_t& v) {
    qfi.first  = true;
    qfi.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::rqi_t& v) {
    rqi.first  = true;
    rqi.second = v;
  }

  //------------------------------------------------------------------------------
  /*
   * void set(const pfcp::paging_policy_indicator_t& v) {
   *   paging_policy_indicator.first = true;
   *   paging_policy_indicator.second = v;
   * }
   */

  //------------------------------------------------------------------------------
  /*
   * void set(const pfcp::averaging_window_t& v) {
   *   averaging_window.false = true;
   *   averaging_window.second = v;
   * }
   */

  //------------------------------------------------------------------------------
  /*
   * void set(const pfcp::qer_control_indication_t& v) {
   *   qer_control_indication.first = true;
   *   qer_control_indication.second = v;
   * }
   */

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
    if (mbr.first) {
      v = mbr.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::gbr_t& v) const {
    if (gbr.first) {
      v = gbr.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::qfi_t& v) const {
    if (qfi.first) {
      v = qfi.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::rqi_t& v) const {
    if (rqi.first) {
      v = rqi.second;
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
  /*
   * Not considered for N4 interface:
   *    std::pair<bool, pfcp::packet_rate_t> packet_rate;
   *    pfcp::dl_flow_level_marking_t dl_flow_level_marking;
   *
   */
  /* bool get(pfcp::packet_rate_t& v) const {
   *   if (packet_rate.first) {
   *    v = packet_rate.second;
   *    return true;
   *   }
   *   return false;
   * }
   *
   */

  /*
   * bool get(pfcp::dl_flow_level_marking_t& v) const {
   *   if (dl_flow_level_marking.first) {
   *     v = dl_flow_level_marking.second;
   *     return true;
   *   }
   *   return false;
   * }
   *
   */

  //------------------------------------------------------------------------------
  /*
   * Types Not Implemented:
   *   pfcp::qer_control_indication_t qer_control_indication;
   *   std::pair<bool, pfcp::packet_rate_status> packet_rate_status; ///?
   */

  /*
   * bool get(pfcp::qer_control_indication_t& v) const {
   *   if (qer_control_indication.first) {
   *     v = qer_control_indication.second;
   *     return true;
   *   }
   *   return false;
   * }
   *
   */

  /*
   * bool get(pfcp::packet_rate_status& v) const {
   *  if (packet_rate_status.first) {
   *     v = packet_rate_status.second;
   *     return true;
   *  }
   *  return false;
   * }
   *
   */

  //------------------------------------------------------------------------------
  /*
   * Optional Parameters:
   *   std::pair<bool, pfcp::averaging_window_t> averaging_window;
   */

  /*
   * bool get(pfcp::averaging_window_t& v) const {
   *  if (averaging_window.first) {
   *     v = averaging_window.second;
   *     return true;
   *  }
   *  return false;
   * }
   *
   */

  //------------------------------------------------------------------------------
  bool update(const pfcp::update_qer& update, uint8_t& cause_value);
};
}  // namespace pfcp

#endif
