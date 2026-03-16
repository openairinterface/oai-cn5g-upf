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

/* Modified by: Franck Messaoudi <franck.messaoudi@eurecom.fr>
 * Date:        2026-03
 * Changes:     Boy Scout cleanup — Doxygen, 3GPP §-refs, separator lines,
 *              setter/getter/update section grouping.
 *              V17.10.0 harmonisation: corrected all §-refs in field
 *              declarations and file-header IE table (all were from an older
 *              spec version — numbering shifted significantly). Added
 *              interface applicability (Sxa/Sxb/Sxc/N4) to all field
 *              comments. Added TODO markers for IEs present in V17.10.0
 *              Table 7.5.2.4-1 but absent from OAI lib's create_urr /
 *              update_urr: Event Threshold (§8.2.113), Event Quota (§8.2.112),
 *              Quota Validity Time (§8.2.132), Subsequent Event Threshold
 *              (§8.2.107), Subsequent Event Quota (§8.2.106), Number of
 *              Reports (§8.2.133), User Plane Inactivity Timer (§8.2.83).
 *              Added Table(s) cross-reference column to IE table header.
 *              Added TODO entries for Exempted App ID for Quota Action and
 *              Exempted SDF Filter for Quota Action (both in 7.5.2.4-1 and
 *              7.5.4.4-1 but absent from lib and from prior IE table).
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 */

/*! \file pfcp_urr.hpp
   \author  Franck MESSAOUDI
   \date 2026
   \email: franck.messaoudi@eurecom.fr

   Control-plane representation of a Usage Reporting Rule (URR).

   Mirrors pfcp::create_urr / pfcp::update_urr from msg_pfcp.hpp exactly.
   SessionProgramManager::ConvertUrr() translates this to the BPF struct
   pfcp_urr (pfcp_urr.h) written into urr_config_map.

   IE layout per 3GPP TS 29.244 V17.10.0 Table 7.5.2.4-1 (Create URR)
   and Table 7.5.4.4-1 (Update URR). See line-comment table below.
*/
// clang-format off
// Information element           P  Field                              §-ref    Sxa Sxb Sxc  N4   Table(s)
// --------------------------------------------------------------------------------------------------------
// URR ID                        M  urr_id                             §8.2.54   X   X   X    X   7.5.2.4-1, 7.5.4.4-1
// Measurement Method            M  measurement_method                 §8.2.40   X   X   X    X   7.5.2.4-1, 7.5.4.4-1
// Reporting Triggers            M  reporting_triggers                 §8.2.19   X   X   X    X   7.5.2.4-1, 7.5.4.4-1
// Measurement Period            C  measurement_period                 §8.2.42   X   X   X    X   7.5.2.4-1, 7.5.4.4-1
// Volume Threshold              C  volume_threshold                   §8.2.13   X   X   X    X   7.5.2.4-1, 7.5.4.4-1
// Volume Quota                  C  volume_quota                       §8.2.50   -   X   X    X   7.5.2.4-1, 7.5.4.4-1
// Event Threshold               C  [TODO - not in lib, §8.2.113]      §8.2.113  -   X   X    X   7.5.2.4-1, 7.5.4.4-1
// Event Quota                   C  [TODO - not in lib, §8.2.112]      §8.2.112  -   X   X    X   7.5.2.4-1, 7.5.4.4-1
// Time Threshold                C  time_threshold                     §8.2.14   X   X   X    X   7.5.2.4-1, 7.5.4.4-1
// Time Quota                    C  time_quota                         §8.2.51   -   X   X    X   7.5.2.4-1, 7.5.4.4-1
// Quota Holding Time            C  quota_holding_time                 §8.2.48   -   X   X    X   7.5.2.4-1, 7.5.4.4-1
// Dropped DL Traffic Threshold  C  dropped_dl_traffic_threshold       §8.2.49   X   -   -    X   7.5.2.4-1, 7.5.4.4-1
// Quota Validity Time           C  [TODO - not in lib, §8.2.132]      §8.2.132  -   X   -    X   7.5.2.4-1, 7.5.4.4-1
// Monitoring Time               O  monitoring_time                    §8.2.15   X   X   X    X   7.5.2.4-1, 7.5.4.4-1
// Subsequent Volume Threshold   O  subsequent_volume_threshold        §8.2.16   X   X   X    X   7.5.2.4-1, 7.5.4.4-1
// Subsequent Time Threshold     O  subsequent_time_threshold          §8.2.17   X   X   X    X   7.5.2.4-1, 7.5.4.4-1
// Subsequent Volume Quota       O  subsequent_volume_quota            §8.2.86   -   X   X    X   7.5.2.4-1, 7.5.4.4-1
// Subsequent Time Quota         O  subsequent_time_quota              §8.2.87   -   X   X    X   7.5.2.4-1, 7.5.4.4-1
// Subsequent Event Threshold    O  [TODO - not in lib, §8.2.107]      §8.2.107  -   X   X    X   7.5.2.4-1, 7.5.4.4-1
// Subsequent Event Quota        O  [TODO - not in lib, §8.2.106]      §8.2.106  -   X   X    X   7.5.2.4-1, 7.5.4.4-1
// Inactivity Detection Time     C  inactivity_detection_time          §8.2.18   -   X   X    X   7.5.2.4-1, 7.5.4.4-1
// Linked URR ID                 C  linked_urr_id                      §8.2.55   -   X   X    X   7.5.2.4-1, 7.5.4.4-1
// Measurement Information       C  measurement_information            §8.2.68   -   X   X    X   7.5.2.4-1, 7.5.4.4-1
// Time Quota Mechanism          C  time_quota_mechanism               §8.2.81   -   X   -    -   7.5.2.4-1, 7.5.4.4-1
// Aggregated URRs               C  aggregated_urrs                    IE 118    -   X   -    -   7.5.2.4-1, 7.5.4.4-1
// FAR ID for Quota Action       C  far_id_for_quota_action            §8.2.74   -   X   X    X   7.5.2.4-1, 7.5.4.4-1
// Ethernet Inactivity Timer     C  ethernet_inactivity_timer          §8.2.105  -   -   -    X   7.5.2.4-1, 7.5.4.4-1
// Additional Monitoring Time    O  additional_monitoring_time         IE 147    X   X   X    X   7.5.2.4-1, 7.5.4.4-1
// Number of Reports             O  [TODO - not in lib, §8.2.133]      §8.2.133  X   X   X    X   7.5.2.4-1, 7.5.4.4-1
// User Plane Inactivity Timer   C  [TODO - type exists in lib but     §8.2.83   -   -   -    X   7.5.2.4-1, 7.5.4.4-1
//                                   not in create_urr/update_urr]
// Exempted App ID for Quota     O  [TODO - not in lib]                §8.2.78   -   X   X    X   7.5.2.4-1, 7.5.4.4-1
// Exempted SDF Filter for Quota O  [TODO - not in lib]                §8.2.5    -   X   X    X   7.5.2.4-1, 7.5.4.4-1
// Event Information             O  event_information (lib grouped IE)  -        -   X   X    X   7.5.2.4-1 only
//                                   event_id + event_threshold §8.2.113
// clang-format on
//
// Availability in OAI PFCP library (msg_pfcp.hpp):
//   All fields present in pfcp::create_urr and pfcp::update_urr EXCEPT:
//   - Event Threshold (§8.2.113) / Event Quota (§8.2.112): lib wraps both
//     into event_information grouped IE; flat IE access not available.
//   - Quota Validity Time (§8.2.132): not in lib.
//   - Subsequent Event Threshold (§8.2.107): not in lib.
//   - Subsequent Event Quota (§8.2.106): not in lib.
//   - Number of Reports (§8.2.133): not in lib.
//   - User Plane Inactivity Timer (§8.2.83): type exists
//     (pfcp::user_plane_inactivity_timer_t) but field absent from
//     create_urr / update_urr structs.
//   Add these fields when the lib is updated.

#ifndef FILE_PFCP_URR_HPP_SEEN
#define FILE_PFCP_URR_HPP_SEEN

#include "msg_pfcp.hpp"

// ---- Reporting Triggers bitmask (3GPP TS 29.244 §8.2.19) -----------------
// Mirrored from pfcp_urr.h so C++ consumers don't depend on kernel
// header include order.
// clang-format off
#ifndef URR_TRIGGER_VOLTH
#define URR_TRIGGER_VOLTH (1U << 0)  ///< Volume Threshold reached
#define URR_TRIGGER_VOLQU (1U << 1)  ///< Volume Quota exhausted
#define URR_TRIGGER_TIMTH (1U << 2)  ///< Time Threshold reached
#define URR_TRIGGER_TIMQU (1U << 3)  ///< Time Quota exhausted
#define URR_TRIGGER_PERIO (1U << 4)  ///< Periodic reporting
#define URR_TRIGGER_START (1U << 5)  ///< Start of traffic detection
#define URR_TRIGGER_STOPT (1U << 6)  ///< Stop of traffic detection
#define URR_TRIGGER_DROTH (1U << 7)  ///< Dropped DL threshold
#endif
// clang-format on

namespace pfcp {

/** @brief Control-plane representation of a Usage Reporting Rule (URR).
 *
 *  Stores all IEs from 3GPP TS 29.244 V17.10.0 Table 7.5.2.4-1 (Create URR)
 *  and Table 7.5.4.4-1 (Update URR). Converted to kernel BPF struct by
 *  SessionProgramManager::ConvertUrr().
 */
class pfcp_urr {
 public:
  // ---- Mandatory -----------------------------------------------------------
  std::pair<bool, pfcp::urr_id_t> urr_id;  ///< §8.2.54 — Sxa+Sxb+Sxc+N4

  // ---- Conditional / Optional ----------------------------------------------
  std::pair<bool, pfcp::measurement_method_t>
      measurement_method;  ///< §8.2.40 — Sxa+Sxb+Sxc+N4
  std::pair<bool, pfcp::reporting_triggers_t>
      reporting_triggers;  ///< §8.2.19 — Sxa+Sxb+Sxc+N4
  std::pair<bool, pfcp::measurement_period_t>
      measurement_period;  ///< §8.2.42 — Sxa+Sxb+Sxc+N4
  std::pair<bool, pfcp::volume_threshold_t>
      volume_threshold;  ///< §8.2.13 — Sxa+Sxb+Sxc+N4
  std::pair<bool, pfcp::volume_quota_t> volume_quota;  ///< §8.2.50 — Sxb+Sxc+N4
  std::pair<bool, pfcp::time_threshold_t>
      time_threshold;  ///< §8.2.14 — Sxa+Sxb+Sxc+N4
  std::pair<bool, pfcp::time_quota_t> time_quota;  ///< §8.2.51 — Sxb+Sxc+N4
  std::pair<bool, pfcp::quota_holding_time_t>
      quota_holding_time;  ///< §8.2.48 — Sxb+Sxc+N4
  std::pair<bool, pfcp::dropped_dl_traffic_threshold_t>
      dropped_dl_traffic_threshold;  ///< §8.2.49 — Sxa+N4
  std::pair<bool, pfcp::monitoring_time_t>
      monitoring_time;  ///< §8.2.15 — Sxa+Sxb+Sxc+N4
  std::pair<bool, pfcp::subsequent_volume_threshold_t>
      subsequent_volume_threshold;  ///< §8.2.16 — Sxa+Sxb+Sxc+N4
  std::pair<bool, pfcp::subsequent_time_threshold_t>
      subsequent_time_threshold;  ///< §8.2.17 — Sxa+Sxb+Sxc+N4
  std::pair<bool, pfcp::subsequent_volume_quota_t>
      subsequent_volume_quota;  ///< §8.2.86 — Sxb+Sxc+N4
  std::pair<bool, pfcp::subsequent_time_quota_t>
      subsequent_time_quota;  ///< §8.2.87 — Sxb+Sxc+N4
  std::pair<bool, pfcp::inactivity_detection_time_t>
      inactivity_detection_time;  ///< §8.2.18 — Sxb+Sxc+N4
  std::pair<bool, pfcp::linked_urr_id_t>
      linked_urr_id;  ///< §8.2.55 — Sxb+Sxc+N4
  std::pair<bool, pfcp::measurement_information_t>
      measurement_information;  ///< §8.2.68 — Sxb+Sxc+N4 (some flags Sxa)
  std::pair<bool, pfcp::time_quota_mechanism_t>
      time_quota_mechanism;  ///< §8.2.81 — Sxb only
  std::pair<bool, pfcp::aggregated_urrs>
      aggregated_urrs;  ///< IE type 118 — Sxb only
  std::pair<bool, pfcp::far_id_t>
      far_id_for_quota_action;  ///< §8.2.74 — Sxb+Sxc+N4
  std::pair<bool, pfcp::ethernet_inactivity_timer_t>
      ethernet_inactivity_timer;  ///< §8.2.105 — N4 only
  std::pair<bool, pfcp::additional_monitoring_time>
      additional_monitoring_time;  ///< IE type 147 — Sxa+Sxb+Sxc+N4
  /// lib grouped IE: event_id + event_threshold (§8.2.113) — Sxb+Sxc+N4
  std::pair<bool, pfcp::event_information> event_information;
  // TODO V17.10.0: Add when lib's create_urr/update_urr are updated:
  //   quota_validity_time          §8.2.132   Sxb+N4
  //   subsequent_event_threshold   §8.2.107   Sxb+Sxc+N4
  //   subsequent_event_quota       §8.2.106   Sxb+Sxc+N4
  //   number_of_reports            §8.2.133   Sxa+Sxb+Sxc+N4
  //   user_plane_inactivity_timer  §8.2.83    N4 only
  //     (type pfcp::user_plane_inactivity_timer_t exists in lib but field
  //      is absent from create_urr/update_urr — add when lib is updated)

  //------------------------------------------------------------------------------
  /** @brief Default constructor — all optional IEs absent. */
  pfcp_urr()
      : urr_id(),
        measurement_method(),
        reporting_triggers(),
        measurement_period(),
        volume_threshold(),
        volume_quota(),
        time_threshold(),
        time_quota(),
        quota_holding_time(),
        dropped_dl_traffic_threshold(),
        monitoring_time(),
        subsequent_volume_threshold(),
        subsequent_time_threshold(),
        subsequent_volume_quota(),
        subsequent_time_quota(),
        inactivity_detection_time(),
        linked_urr_id(),
        measurement_information(),
        time_quota_mechanism(),
        aggregated_urrs(),
        far_id_for_quota_action(),
        ethernet_inactivity_timer(),
        additional_monitoring_time(),
        event_information() {}

  //------------------------------------------------------------------------------
  /** @brief Construct from Create URR IE
   *         (3GPP TS 29.244 V17.10.0 Table 7.5.2.4-1).
   */
  explicit pfcp_urr(const pfcp::create_urr& c)
      : urr_id(c.urr_id),
        measurement_method(c.measurement_method),
        reporting_triggers(c.reporting_triggers),
        measurement_period(c.measurement_period),
        volume_threshold(c.volume_threshold),
        volume_quota(c.volume_quota),
        time_threshold(c.time_threshold),
        time_quota(c.time_quota),
        quota_holding_time(c.quota_holding_time),
        dropped_dl_traffic_threshold(c.dropped_dl_traffic_threshold),
        monitoring_time(c.monitoring_time),
        subsequent_volume_threshold(c.subsequent_volume_threshold),
        subsequent_time_threshold(c.subsequent_time_threshold),
        subsequent_volume_quota(c.subsequent_volume_quota),
        subsequent_time_quota(c.subsequent_time_quota),
        inactivity_detection_time(c.inactivity_detection_time),
        linked_urr_id(c.linked_urr_id),
        measurement_information(c.measurement_information),
        time_quota_mechanism(c.time_quota_mechanism),
        aggregated_urrs(c.aggregated_urrs),
        far_id_for_quota_action(c.far_id_for_quota_action),
        ethernet_inactivity_timer(c.ethernet_inactivity_timer),
        additional_monitoring_time(c.additional_monitoring_time),
        event_information(c.event_information) {}

  //------------------------------------------------------------------------------
  /** @brief Copy constructor. */
  pfcp_urr(const pfcp_urr& c)
      : urr_id(c.urr_id),
        measurement_method(c.measurement_method),
        reporting_triggers(c.reporting_triggers),
        measurement_period(c.measurement_period),
        volume_threshold(c.volume_threshold),
        volume_quota(c.volume_quota),
        time_threshold(c.time_threshold),
        time_quota(c.time_quota),
        quota_holding_time(c.quota_holding_time),
        dropped_dl_traffic_threshold(c.dropped_dl_traffic_threshold),
        monitoring_time(c.monitoring_time),
        subsequent_volume_threshold(c.subsequent_volume_threshold),
        subsequent_time_threshold(c.subsequent_time_threshold),
        subsequent_volume_quota(c.subsequent_volume_quota),
        subsequent_time_quota(c.subsequent_time_quota),
        inactivity_detection_time(c.inactivity_detection_time),
        linked_urr_id(c.linked_urr_id),
        measurement_information(c.measurement_information),
        time_quota_mechanism(c.time_quota_mechanism),
        aggregated_urrs(c.aggregated_urrs),
        far_id_for_quota_action(c.far_id_for_quota_action),
        ethernet_inactivity_timer(c.ethernet_inactivity_timer),
        additional_monitoring_time(c.additional_monitoring_time),
        event_information(c.event_information) {}

  // ---- Setters -------------------------------------------------------------

  //------------------------------------------------------------------------------
  void set(const pfcp::urr_id_t& v) {
    urr_id.first  = true;
    urr_id.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::measurement_method_t& v) {
    measurement_method.first  = true;
    measurement_method.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::reporting_triggers_t& v) {
    reporting_triggers.first  = true;
    reporting_triggers.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::measurement_period_t& v) {
    measurement_period.first  = true;
    measurement_period.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::volume_threshold_t& v) {
    volume_threshold.first  = true;
    volume_threshold.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::volume_quota_t& v) {
    volume_quota.first  = true;
    volume_quota.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::time_threshold_t& v) {
    time_threshold.first  = true;
    time_threshold.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::time_quota_t& v) {
    time_quota.first  = true;
    time_quota.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::quota_holding_time_t& v) {
    quota_holding_time.first  = true;
    quota_holding_time.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::dropped_dl_traffic_threshold_t& v) {
    dropped_dl_traffic_threshold.first  = true;
    dropped_dl_traffic_threshold.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::monitoring_time_t& v) {
    monitoring_time.first  = true;
    monitoring_time.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::subsequent_volume_threshold_t& v) {
    subsequent_volume_threshold.first  = true;
    subsequent_volume_threshold.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::subsequent_time_threshold_t& v) {
    subsequent_time_threshold.first  = true;
    subsequent_time_threshold.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::subsequent_volume_quota_t& v) {
    subsequent_volume_quota.first  = true;
    subsequent_volume_quota.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::subsequent_time_quota_t& v) {
    subsequent_time_quota.first  = true;
    subsequent_time_quota.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::inactivity_detection_time_t& v) {
    inactivity_detection_time.first  = true;
    inactivity_detection_time.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::linked_urr_id_t& v) {
    linked_urr_id.first  = true;
    linked_urr_id.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::measurement_information_t& v) {
    measurement_information.first  = true;
    measurement_information.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::time_quota_mechanism_t& v) {
    time_quota_mechanism.first  = true;
    time_quota_mechanism.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::aggregated_urrs& v) {
    aggregated_urrs.first  = true;
    aggregated_urrs.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::far_id_t& v) {
    far_id_for_quota_action.first  = true;
    far_id_for_quota_action.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::ethernet_inactivity_timer_t& v) {
    ethernet_inactivity_timer.first  = true;
    ethernet_inactivity_timer.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::additional_monitoring_time& v) {
    additional_monitoring_time.first  = true;
    additional_monitoring_time.second = v;
  }

  //------------------------------------------------------------------------------
  void set(const pfcp::event_information& v) {
    event_information.first  = true;
    event_information.second = v;
  }

  // ---- Getters -------------------------------------------------------------

  //------------------------------------------------------------------------------
  bool get(pfcp::urr_id_t& v) const {
    if (urr_id.first) {
      v = urr_id.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::measurement_method_t& v) const {
    if (measurement_method.first) {
      v = measurement_method.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::reporting_triggers_t& v) const {
    if (reporting_triggers.first) {
      v = reporting_triggers.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::measurement_period_t& v) const {
    if (measurement_period.first) {
      v = measurement_period.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::volume_threshold_t& v) const {
    if (volume_threshold.first) {
      v = volume_threshold.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::volume_quota_t& v) const {
    if (volume_quota.first) {
      v = volume_quota.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::time_threshold_t& v) const {
    if (time_threshold.first) {
      v = time_threshold.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::time_quota_t& v) const {
    if (time_quota.first) {
      v = time_quota.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::quota_holding_time_t& v) const {
    if (quota_holding_time.first) {
      v = quota_holding_time.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::dropped_dl_traffic_threshold_t& v) const {
    if (dropped_dl_traffic_threshold.first) {
      v = dropped_dl_traffic_threshold.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::monitoring_time_t& v) const {
    if (monitoring_time.first) {
      v = monitoring_time.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::subsequent_volume_threshold_t& v) const {
    if (subsequent_volume_threshold.first) {
      v = subsequent_volume_threshold.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::subsequent_time_threshold_t& v) const {
    if (subsequent_time_threshold.first) {
      v = subsequent_time_threshold.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::subsequent_volume_quota_t& v) const {
    if (subsequent_volume_quota.first) {
      v = subsequent_volume_quota.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::subsequent_time_quota_t& v) const {
    if (subsequent_time_quota.first) {
      v = subsequent_time_quota.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::inactivity_detection_time_t& v) const {
    if (inactivity_detection_time.first) {
      v = inactivity_detection_time.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::linked_urr_id_t& v) const {
    if (linked_urr_id.first) {
      v = linked_urr_id.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::measurement_information_t& v) const {
    if (measurement_information.first) {
      v = measurement_information.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::time_quota_mechanism_t& v) const {
    if (time_quota_mechanism.first) {
      v = time_quota_mechanism.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::aggregated_urrs& v) const {
    if (aggregated_urrs.first) {
      v = aggregated_urrs.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::far_id_t& v) const {
    if (far_id_for_quota_action.first) {
      v = far_id_for_quota_action.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::ethernet_inactivity_timer_t& v) const {
    if (ethernet_inactivity_timer.first) {
      v = ethernet_inactivity_timer.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::additional_monitoring_time& v) const {
    if (additional_monitoring_time.first) {
      v = additional_monitoring_time.second;
      return true;
    }
    return false;
  }

  //------------------------------------------------------------------------------
  bool get(pfcp::event_information& v) const {
    if (event_information.first) {
      v = event_information.second;
      return true;
    }
    return false;
  }

  // ---- Update --------------------------------------------------------------

  //------------------------------------------------------------------------------
  /** @brief Apply Update URR IE fields
   *         (3GPP TS 29.244 V17.10.0 Table 7.5.4.4-1).
   *  @param u           Update URR message IE.
   *  @param cause_value Populated with CAUSE_VALUE_* on return.
   *  @return true on success.
   */
  bool update(const pfcp::update_urr& u, uint8_t& cause_value);
};

}  // namespace pfcp

#endif  // FILE_PFCP_URR_HPP_SEEN
