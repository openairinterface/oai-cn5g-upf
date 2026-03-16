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
 * Changes:     Boy Scout cleanup — Doxygen, 3GPP §-refs, separator lines.
 *              V17.10.0 harmonisation: corrected §-refs on all update() IE
 *              lines and table reference in function comment. No structural
 *              changes — URR tables are identical between V17.6.0 and
 *              V17.10.0 (no URR-specific CRs in that range).
 *              Added TODO stubs with table refs (7.5.4.4-1) for all IEs
 *              missing from lib: Subsequent Event Threshold §8.2.107,
 *              Subsequent Event Quota §8.2.106, Number of Reports §8.2.133,
 *              User Plane Inactivity Timer §8.2.83, Exempted App ID for
 *              Quota Action §8.2.78, Exempted SDF Filter for Quota Action
 *              §8.2.5.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 */

/*! \file pfcp_urr.cpp
   \author  Franck MESSAOUDI
   \date 2026
   \email: franck.messaoudi@eurecom.fr
*/

#include "pfcp_urr.hpp"

using namespace pfcp;

//------------------------------------------------------------------------------
// pfcp_urr::update — Apply Update URR IE (Table 7.5.4.4-1).
// Each field is overwritten only if present in the Update URR message.
// Fields absent from the Update URR IE retain their previously established
// values per §7.5.4.4 NOTE 1.

//------------------------------------------------------------------------------
bool pfcp_urr::update(const pfcp::update_urr& u, uint8_t& cause_value) {
  // 3GPP TS 29.244 V17.10.0 Table 7.5.4.4-1 — Update URR IEs
  if (u.get(measurement_method.second))
    measurement_method.first = true;  // §8.2.40 — Sxa+Sxb+Sxc+N4
  if (u.get(reporting_triggers.second))
    reporting_triggers.first = true;  // §8.2.19 — Sxa+Sxb+Sxc+N4
  if (u.get(measurement_period.second))
    measurement_period.first = true;  // §8.2.42 — Sxa+Sxb+Sxc+N4
  if (u.get(volume_threshold.second))
    volume_threshold.first = true;  // §8.2.13 — Sxa+Sxb+Sxc+N4
  if (u.get(volume_quota.second))
    volume_quota.first = true;  // §8.2.50 — Sxb+Sxc+N4
  if (u.get(time_threshold.second))
    time_threshold.first = true;  // §8.2.14 — Sxa+Sxb+Sxc+N4
  if (u.get(time_quota.second))
    time_quota.first = true;  // §8.2.51 — Sxb+Sxc+N4
  if (u.get(quota_holding_time.second))
    quota_holding_time.first = true;  // §8.2.48 — Sxb+Sxc+N4
  if (u.get(dropped_dl_traffic_threshold.second))
    dropped_dl_traffic_threshold.first = true;  // §8.2.49 — Sxa+N4
  if (u.get(monitoring_time.second))
    monitoring_time.first = true;  // §8.2.15 — Sxa+Sxb+Sxc+N4
  if (u.get(subsequent_volume_threshold.second))
    subsequent_volume_threshold.first = true;  // §8.2.16 — Sxa+Sxb+Sxc+N4
  if (u.get(subsequent_time_threshold.second))
    subsequent_time_threshold.first = true;  // §8.2.17 — Sxa+Sxb+Sxc+N4
  if (u.get(subsequent_volume_quota.second))
    subsequent_volume_quota.first = true;  // §8.2.86 — Sxb+Sxc+N4
  if (u.get(subsequent_time_quota.second))
    subsequent_time_quota.first = true;  // §8.2.87 — Sxb+Sxc+N4
  if (u.get(inactivity_detection_time.second))
    inactivity_detection_time.first = true;  // §8.2.18 — Sxb+Sxc+N4
  if (u.get(linked_urr_id.second))
    linked_urr_id.first = true;  // §8.2.55 — Sxb+Sxc+N4
  if (u.get(measurement_information.second))
    measurement_information.first = true;  // §8.2.68 — Sxb+Sxc+N4
  if (u.get(time_quota_mechanism.second))
    time_quota_mechanism.first = true;  // §8.2.81 — Sxb only
  if (u.get(aggregated_urrs.second))
    aggregated_urrs.first = true;  // IE type 118 — Sxb only
  if (u.get(far_id_for_quota_action.second))
    far_id_for_quota_action.first = true;  // §8.2.74 — Sxb+Sxc+N4
  if (u.get(ethernet_inactivity_timer.second))
    ethernet_inactivity_timer.first = true;  // §8.2.105 — N4 only
  if (u.get(additional_monitoring_time.second))
    additional_monitoring_time.first = true;  // IE type 147 — Sxa+Sxb+Sxc+N4

  // TODO §8.2.107 — Subsequent Event Threshold (O, Sxb+Sxc+N4, Table 7.5.4.4-1)
  //   update_urr does not carry this IE (lib gap). Add when lib is updated.
  // TODO §8.2.106 — Subsequent Event Quota (O, Sxb+Sxc+N4, Table 7.5.4.4-1)
  //   update_urr does not carry this IE (lib gap). Add when lib is updated.
  // TODO §8.2.133 — Number of Reports (O, Sxa+Sxb+Sxc+N4, Table 7.5.4.4-1)
  //   update_urr does not carry this IE (lib gap). Add when lib is updated.
  // TODO §8.2.83  — User Plane Inactivity Timer (C, N4, Table 7.5.4.4-1)
  //   Type pfcp::user_plane_inactivity_timer_t exists in lib but field absent
  //   from update_urr. Add when lib is updated.
  // TODO §8.2.78  — Exempted Application ID for Quota Action (O, Sxb+Sxc+N4,
  //   Tables 7.5.2.4-1, 7.5.4.4-1). Not in lib. Add when lib is updated.
  // TODO §8.2.5   — Exempted SDF Filter for Quota Action (O, Sxb+Sxc+N4,
  //   Tables 7.5.2.4-1, 7.5.4.4-1). Not in lib. Add when lib is updated.

  if (u.get(event_information.second))
    event_information.first =
        true;  // grouped IE: event_id+threshold (7.5.4.4-1)
  return true;
}
