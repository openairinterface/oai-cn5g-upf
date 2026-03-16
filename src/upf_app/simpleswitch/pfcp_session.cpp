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

// clang-format off
/* Modified by: Franck Messaoudi <franck.messaoudi@eurecom.fr>
 * Date:        2026-03
 * Changes:     Boy Scout cleanup — Doxygen, 3GPP §-refs.
 *              Bug fix: pfcp_session::update(bar) replaced incompatible direct
 *              pair assignments with explicit field-by-field conversion.
 *              V17.10.0 harmonisation: renamed dl_buffering_suggested_packet_
 *              count → downlink_data_notification_delay in BAR update block
 *              (the old name stored a delay, not a packet count). Fixed §-refs:
 *              BAR ID §8.2.57 (was §8.2.49), SugBuffPktCnt §8.2.100 (was
 *              §8.2.50). See pfcp_bar.hpp for full BAR IE applicability table.
 *              MAR block: fixed table refs (create_mar 7.5.2.9-1 → 7.5.2.8-1,
 *              remove_mar 7.5.4.14-1 → 7.5.4.15-1). Fixed silent bug: weight_
 *              present and priority_present were never set after copying weight/
 *              priority from AFAI in create_mar and the update_mar lambda.
 *              Added TODO markers for V17.10.0 new IEs not yet in OAI lib:
 *              RAT Type in AFAI (§8.2.186), Thresholds (§8.2.196), Steering
 *              Mode Indicator (§8.2.197).
 *              V17.10.0 audit pass (2026-03):
 *                - Fixed PDN Type section header §-ref: §8.2.38 (= Node ID)
 *                  → §8.2.79 (= PDN Type).
 *                - Bug fix: create_far(), create_pdr(), create_qer() all
 *                  missing cause.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED
 *                  on the success path — same bug pattern fixed in far/qer/
 *                  pdr/bar/urr/mar in earlier sessions.
 *                - Fixed create_qer comment §8.2.20/§8.2.21 (= Redirect
 *                  Info / Report Type) → §8.2.8 (MBR) / §8.2.9 (GBR).
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 */
// clang-format on

/*! \file pfcp_session.cpp
   \author  Lionel GAUTHIER
   \date 2019
   \email: lionel.gauthier@eurecom.fr
*/

#include "pfcp_session.hpp"

#include <arpa/inet.h>

#include <sstream>

#include "logger.hpp"
#include "pfcp_switch.hpp"

using namespace pfcp;
using namespace oai::upf::app;

extern pfcp_switch* pfcp_switch_inst;

enum pfcp_gate_status_value { PFCP_GATE_OPEN = 0, PFCP_GATE_CLOSED = 1 };

// =============================================================================
// TEID / PDN-type accessors
// =============================================================================

//------------------------------------------------------------------------------
void pfcp_session::set(const pfcp::fteid_t& fteid) {
  Logger::upf_n4().info("pfcp_session::set(fteid) seid " SEID_FMT " ", seid);
  std::lock_guard<std::mutex> lock(teid_mutex);
  teid_uplink = fteid;
}

//------------------------------------------------------------------------------
bool pfcp_session::get(pfcp::fteid_t& fteid) {
  std::lock_guard<std::mutex> lock(teid_mutex);
  Logger::upf_n4().info("pfcp_session::get(fteid) seid " SEID_FMT " ", seid);
  fteid = teid_uplink;
  return true;
}

//------------------------------------------------------------------------------
// PDN Type (3GPP TS 29.244 V17.10.0 §8.2.79)

//------------------------------------------------------------------------------
void pfcp_session::set(pfcp::pdn_type_value_e type) {
  std::lock_guard<std::mutex> lock(pdn_type_mutex);
  pdn_type = type;
}

//------------------------------------------------------------------------------
pfcp::pdn_type_value_e pfcp_session::get_pdn_type() {
  return pdn_type;
}

// =============================================================================
// Lookup by ID
// =============================================================================

//------------------------------------------------------------------------------
// FAR lookup — O(n) linear scan; n is small (≤8 per session in practice)

//------------------------------------------------------------------------------
bool pfcp_session::get(
    const uint32_t far_id, std::shared_ptr<pfcp::pfcp_far>& far) const {
  for (auto it : fars) {
    if (it->far_id.far_id == far_id) {
      far = it;
      return true;
    }
  }
  return false;
}

//------------------------------------------------------------------------------
bool pfcp_session::get(
    const uint16_t pdr_id, std::shared_ptr<pfcp::pfcp_pdr>& pdr) const {
  for (auto it : pdrs) {
    if (it->pdr_id.rule_id == pdr_id) {
      pdr = it;
      return true;
    }
  }
  return false;
}

//------------------------------------------------------------------------------
bool pfcp_session::get(
    const uint32_t qer_id, std::shared_ptr<pfcp::pfcp_qer>& qer) const {
  for (auto it : qers) {
    if (it->qer_id.first && it->qer_id.second.qer_id == qer_id) {
      qer = it;
      return true;
    }
  }
  return false;
}

//------------------------------------------------------------------------------
bool pfcp_session::get(
    const uint32_t urr_id, std::shared_ptr<pfcp::pfcp_urr>& urr) const {
  for (const auto& it : urrs) {
    if (it->urr_id.first && it->urr_id.second.urr_id == urr_id) {
      urr = it;
      return true;
    }
  }
  return false;
}

//------------------------------------------------------------------------------
bool pfcp_session::get(
    const uint8_t bar_id, std::shared_ptr<pfcp::pfcp_bar>& bar) const {
  for (const auto& it : bars) {
    if (it->bar_id.first && it->bar_id.second.bar_id == bar_id) {
      bar = it;
      return true;
    }
  }
  return false;
}

//------------------------------------------------------------------------------
bool pfcp_session::get(
    const uint8_t mar_id, std::shared_ptr<pfcp::pfcp_mar>& mar) const {
  for (const auto& it : mars) {
    if (it->mar_id.first && it->mar_id.second.mar_id == mar_id) {
      mar = it;
      return true;
    }
  }
  return false;
}

// =============================================================================
// add() — internal upsert helpers
// =============================================================================

//------------------------------------------------------------------------------
// add(far) — if a FAR with the same ID already exists, patch the TEID only;
// otherwise append. Keeps the vector compact (no duplicates).

//------------------------------------------------------------------------------
void pfcp_session::add(std::shared_ptr<pfcp::pfcp_far> far) {
  uint32_t far_id = far->far_id.far_id;

  Logger::upf_n4().info(
      "pfcp_session::add(far) seid " SEID_FMT " FAR=%u", seid, far_id);

  // Check if FAR already exists (update case)
  for (auto it = fars.begin(); it != fars.end(); ++it) {
    if ((*it)->far_id.far_id == far_id) {
      Logger::upf_n4().info(
          "  └─ Updating existing FAR %u in session " SEID_FMT, far_id, seid);

      // Log what's being updated
      if (far->forwarding_parameters.first &&
          far->forwarding_parameters.second.outer_header_creation.first) {
        uint32_t old_teid = (*it)
                                ->forwarding_parameters.second
                                .outer_header_creation.second.teid;
        uint32_t new_teid =
            far->forwarding_parameters.second.outer_header_creation.second.teid;

        if (old_teid != new_teid) {
          Logger::upf_n4().debug(
              "     • TEID update: 0x%x → 0x%x", old_teid, new_teid);
        }

        (*it)->forwarding_parameters.second.outer_header_creation.second.teid =
            new_teid;
      }
      return;
    }
  }

  // Add new FAR
  Logger::upf_n4().info(
      "  └─ Adding new FAR %u to session " SEID_FMT, far_id, seid);

  // Log apply action
  if (far->apply_action.forw || far->apply_action.drop ||
      far->apply_action.buff || far->apply_action.nocp) {
    std::ostringstream actions;
    if (far->apply_action.forw) actions << "FORW ";
    if (far->apply_action.drop) actions << "DROP ";
    if (far->apply_action.buff) actions << "BUFF ";
    if (far->apply_action.nocp) actions << "NOCP";
    Logger::upf_n4().debug("     • Apply Action: %s", actions.str().c_str());
  }

  // Log forwarding parameters
  if (far->forwarding_parameters.first) {
    auto& params = far->forwarding_parameters.second;

    if (params.destination_interface.first) {
      uint8_t iface = params.destination_interface.second.interface_value;
      const char* dest_str = "UNKNOWN";
      switch (iface) {
        case INTERFACE_VALUE_ACCESS:
          dest_str = "ACCESS";
          break;
        case INTERFACE_VALUE_CORE:
          dest_str = "CORE";
          break;
        case INTERFACE_VALUE_CP_FUNCTION:
          dest_str = "CP_FUNCTION";
          break;
        default:
          break;
      }
      Logger::upf_n4().debug("     • Destination Interface: %s", dest_str);

      if (params.outer_header_creation.first) {
        uint32_t teid = params.outer_header_creation.second.teid;
        Logger::upf_n4().debug("     • Outer Header TEID: 0x%x", teid);

        // Log IP address if present
        if (params.outer_header_creation.second
                .outer_header_creation_description ==
            OUTER_HEADER_CREATION_GTPU_UDP_IPV4) {
          char ip_str[INET_ADDRSTRLEN];
          inet_ntop(
              AF_INET, &params.outer_header_creation.second.ipv4_address,
              ip_str, INET_ADDRSTRLEN);
          Logger::upf_n4().debug("     • Remote IP: %s", ip_str);
        }
      }
    }
  }

  fars.push_back(far);
  Logger::upf_n4().debug("     • Total FARs in session: %zu", fars.size());
}

//------------------------------------------------------------------------------
void pfcp_session::add(std::shared_ptr<pfcp::pfcp_pdr> pdr) {
  uint16_t pdr_id = pdr->pdr_id.rule_id;

  Logger::upf_n4().info(
      "pfcp_session::add(pdr) seid " SEID_FMT " PDR=%u", seid, pdr_id);

  // Check for duplicate PDR
  for (auto& existing_pdr : pdrs) {
    if (existing_pdr->pdr_id.rule_id == pdr_id) {
      Logger::upf_n4().warn(
          "  └─ Skipping duplicate PDR %u in session " SEID_FMT
          " - already exists",
          pdr_id, seid);
      return;
    }
  }

  // Add new PDR
  Logger::upf_n4().info(
      "  └─ Adding new PDR %u to session " SEID_FMT, pdr_id, seid);

  // Log PDI (Packet Detection Information)
  if (pdr->pdi.first) {
    auto& pdi = pdr->pdi.second;

    // Source interface
    if (pdi.source_interface.first) {
      uint8_t iface       = pdi.source_interface.second.interface_value;
      const char* dir_str = "UNKNOWN";
      switch (iface) {
        case INTERFACE_VALUE_ACCESS:
          dir_str = "ACCESS (Uplink)";
          break;
        case INTERFACE_VALUE_CORE:
          dir_str = "CORE (Downlink)";
          break;
        case INTERFACE_VALUE_CP_FUNCTION:
          dir_str = "CP_FUNCTION";
          break;
        default:
          break;
      }
      Logger::upf_n4().debug("     • Source Interface: %s", dir_str);
    }

    // Local F-TEID (for uplink)
    if (pdi.local_fteid.first) {
      uint32_t teid = pdi.local_fteid.second.teid;
      Logger::upf_n4().debug("     • Local F-TEID: 0x%x", teid);
    }

    // UE IP address (for downlink)
    if (pdi.ue_ip_address.first && pdi.ue_ip_address.second.v4) {
      char ip_str[INET_ADDRSTRLEN];
      inet_ntop(
          AF_INET, &pdi.ue_ip_address.second.ipv4_address, ip_str,
          INET_ADDRSTRLEN);
      Logger::upf_n4().debug("     • UE IP Address: %s", ip_str);
    }
  }

  // Log precedence
  if (pdr->precedence.first) {
    Logger::upf_n4().debug(
        "     • Precedence: %u", pdr->precedence.second.precedence);
  }

  // Log linked FAR
  if (pdr->far_id.first) {
    Logger::upf_n4().debug("     • Linked FAR: %u", pdr->far_id.second.far_id);
  }

  // Log linked QER
  if (pdr->qer_id.first) {
    Logger::upf_n4().debug("     • Linked QER: %u", pdr->qer_id.second.qer_id);
  }

  // Log linked URR
  if (pdr->urr_id.first) {
    Logger::upf_n4().debug("     • Linked URR: %u", pdr->urr_id.second.urr_id);
  }

  pdrs.push_back(pdr);
  Logger::upf_n4().debug("     • Total PDRs in session: %zu", pdrs.size());
}

//------------------------------------------------------------------------------
void pfcp_session::add(std::shared_ptr<pfcp::pfcp_qer> qer) {
  // Guard .first before accessing .second — qer_id is M per Table 7.5.2.5-1
  // but defensive coding costs nothing.
  if (!qer->qer_id.first) {
    Logger::upf_n4().warn(
        "pfcp_session::add(qer) seid " SEID_FMT " — QER ID absent, skipping",
        seid);
    return;
  }

  uint32_t qer_id = qer->qer_id.second.qer_id;
  uint8_t qfi     = qer->qos_flow_id.first ? qer->qos_flow_id.second.qfi : 0;

  Logger::upf_n4().info(
      "pfcp_session::add(qer) seid " SEID_FMT " QER=%u", seid, qer_id);

  // Check for duplicate QER
  for (auto& existing_qer : qers) {
    if (existing_qer->qer_id.second.qer_id == qer_id) {
      Logger::upf_n4().warn(
          "  └─ Skipping duplicate QER %u (QFI %u) in session " SEID_FMT
          " - already exists",
          qer_id, qfi, seid);
      return;
    }
  }

  // Add new QER
  Logger::upf_n4().info(
      "  └─ Adding new QER %u to session " SEID_FMT, qer_id, seid);

  // Log QoS Flow Identifier
  Logger::upf_n4().debug("     • QFI (QoS Flow ID): %u", qfi);

  // Log Gate Status
  if (qer->gate_status.first) {
    const char* ul_gate =
        (qer->gate_status.second.ul_gate == PFCP_GATE_OPEN) ? "OPEN" : "CLOSED";
    const char* dl_gate =
        (qer->gate_status.second.dl_gate == PFCP_GATE_OPEN) ? "OPEN" : "CLOSED";

    Logger::upf_n4().debug(
        "     • Gate Status: UL=%s, DL=%s", ul_gate, dl_gate);
  }

  // Log Guaranteed Bit Rate (GBR)
  if (qer->guaranteed_bitrate.first) {
    uint64_t gbr_ul = qer->guaranteed_bitrate.second.ul_gbr;
    uint64_t gbr_dl = qer->guaranteed_bitrate.second.dl_gbr;
    Logger::upf_n4().debug(
        "     • GBR: UL=%llu kbps, DL=%llu kbps", gbr_ul, gbr_dl);
  }

  // Log Maximum Bit Rate (MBR)
  if (qer->maximum_bitrate.first) {
    uint64_t mbr_ul = qer->maximum_bitrate.second.ul_mbr;
    uint64_t mbr_dl = qer->maximum_bitrate.second.dl_mbr;
    Logger::upf_n4().debug(
        "     • MBR: UL=%llu kbps, DL=%llu kbps", mbr_ul, mbr_dl);
  }

  // Log QER Correlation ID
  if (qer->qer_correlation_id.first) {
    Logger::upf_n4().debug(
        "     • QER Correlation ID: %u",
        qer->qer_correlation_id.second.qer_correlation_id);
  }

  // Log Reflective QoS
  if (qer->reflective_qos.first) {
    Logger::upf_n4().debug(
        "     • Reflective QoS: %s",
        qer->reflective_qos.second.rqi ? "Enabled" : "Disabled");
  }

  // Log Paging Policy Indicator
  if (qer->paging_policy_indicator.first) {
    Logger::upf_n4().debug(
        "     • Paging Policy Indicator: %u",
        qer->paging_policy_indicator.second.ppi_value);
  }

  // Log Averaging Window
  if (qer->averaging_window.first) {
    Logger::upf_n4().debug(
        "     • Averaging Window: %u ms",
        qer->averaging_window.second.averaging_window);
  }

  qers.push_back(qer);
  Logger::upf_n4().debug("     • Total QERs in session: %zu", qers.size());
}

// =============================================================================
// URR — add / create / update / remove
// =============================================================================

//------------------------------------------------------------------------------
void pfcp_session::add(std::shared_ptr<pfcp::pfcp_urr> urr) {
  uint32_t urr_id = urr->urr_id.second.urr_id;
  Logger::upf_n4().info(
      "pfcp_session::add(urr) seid " SEID_FMT " URR=%u", seid, urr_id);
  for (auto it = urrs.begin(); it != urrs.end(); ++it) {
    if ((*it)->urr_id.second.urr_id == urr_id) {
      Logger::upf_n4().info(
          "  └─ Replacing existing URR %u in session " SEID_FMT, urr_id, seid);
      *it = urr;
      return;
    }
  }
  Logger::upf_n4().info(
      "  └─ Adding new URR %u to session " SEID_FMT, urr_id, seid);
  urrs.push_back(urr);
  Logger::upf_n4().debug("     • Total URRs in session: %zu", urrs.size());
}

//------------------------------------------------------------------------------
// create_urr — 3GPP TS 29.244 Table 7.5.2.4-1
// Mandatory IEs: URR ID, Measurement Method, Reporting Triggers

//------------------------------------------------------------------------------
bool pfcp_session::create(
    const pfcp::create_urr& cr_urr, pfcp::cause_t& cause,
    uint16_t& offending_ie) {
  if (not cr_urr.urr_id.first) {
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie      = PFCP_IE_URR_ID;
    return false;
  }
  if (not cr_urr.measurement_method.first) {
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie      = PFCP_IE_MEASUREMENT_METHOD;
    return false;
  }
  if (not cr_urr.reporting_triggers.first) {
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie      = PFCP_IE_REPORTING_TRIGGERS;
    return false;
  }
  auto urr = std::make_shared<pfcp::pfcp_urr>(cr_urr);
  add(urr);
  cause.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
  return true;
}

//------------------------------------------------------------------------------
// update_urr — 3GPP TS 29.244 Table 7.5.4.4-1

//------------------------------------------------------------------------------
bool pfcp_session::update(
    const pfcp::update_urr& urr_update, uint8_t& cause_value) {
  if (not urr_update.urr_id.first) {
    cause_value = CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE;
    return false;
  }
  uint32_t urr_id = urr_update.urr_id.second.urr_id;
  Logger::upf_n4().info(
      "pfcp_session::update(urr) seid " SEID_FMT " URR=%u", seid, urr_id);
  for (auto& existing : urrs) {
    if (existing->urr_id.second.urr_id == urr_id) {
      if (urr_update.measurement_method.first)
        existing->measurement_method = urr_update.measurement_method;
      if (urr_update.reporting_triggers.first)
        existing->reporting_triggers = urr_update.reporting_triggers;
      if (urr_update.measurement_period.first)
        existing->measurement_period = urr_update.measurement_period;
      if (urr_update.volume_threshold.first)
        existing->volume_threshold = urr_update.volume_threshold;
      if (urr_update.volume_quota.first)
        existing->volume_quota = urr_update.volume_quota;
      if (urr_update.time_threshold.first)
        existing->time_threshold = urr_update.time_threshold;
      if (urr_update.time_quota.first)
        existing->time_quota = urr_update.time_quota;
      if (urr_update.quota_holding_time.first)
        existing->quota_holding_time = urr_update.quota_holding_time;
      if (urr_update.monitoring_time.first)
        existing->monitoring_time = urr_update.monitoring_time;
      if (urr_update.linked_urr_id.first)
        existing->linked_urr_id = urr_update.linked_urr_id;
      Logger::upf_n4().info(
          "  └─ Updated URR %u in session " SEID_FMT, urr_id, seid);
      cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
      return true;
    }
  }
  Logger::upf_n4().warn(
      "  └─ URR %u not found in session " SEID_FMT " - cannot update", urr_id,
      seid);
  cause_value = CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE;
  return false;
}

//------------------------------------------------------------------------------
// remove_urr — 3GPP TS 29.244 Table 7.5.4.8-1

//------------------------------------------------------------------------------
bool pfcp_session::remove(
    const pfcp::remove_urr& rm_urr, pfcp::cause_t& cause,
    uint16_t& offending_ie) {
  if (not rm_urr.urr_id.first) {
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie      = PFCP_IE_URR_ID;
    return false;
  }
  uint32_t urr_id = rm_urr.urr_id.second.urr_id;
  Logger::upf_n4().info(
      "pfcp_session::remove(urr) seid " SEID_FMT " URR=%u", seid, urr_id);
  for (auto it = urrs.begin(); it != urrs.end(); ++it) {
    if ((*it)->urr_id.second.urr_id == urr_id) {
      urrs.erase(it);
      Logger::upf_n4().info(
          "  └─ Removed URR %u from session " SEID_FMT " (%zu URRs remaining)",
          urr_id, seid, urrs.size());
      cause.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
      return true;
    }
  }
  Logger::upf_n4().warn(
      "  └─ URR %u not found in session " SEID_FMT " - cannot remove", urr_id,
      seid);
  cause.cause_value = CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE;
  offending_ie      = PFCP_IE_URR_ID;
  return false;
}

// =============================================================================
// BAR — add / create / update / remove
// =============================================================================

//------------------------------------------------------------------------------
void pfcp_session::add(std::shared_ptr<pfcp::pfcp_bar> bar) {
  uint8_t bar_id = bar->bar_id.second.bar_id;
  Logger::upf_n4().info(
      "pfcp_session::add(bar) seid " SEID_FMT " BAR=%u", seid, bar_id);
  for (auto it = bars.begin(); it != bars.end(); ++it) {
    if ((*it)->bar_id.second.bar_id == bar_id) {
      Logger::upf_n4().info(
          "  └─ Replacing existing BAR %u in session " SEID_FMT, bar_id, seid);
      *it = bar;
      return;
    }
  }
  Logger::upf_n4().info(
      "  └─ Adding new BAR %u to session " SEID_FMT, bar_id, seid);
  bars.push_back(bar);
  Logger::upf_n4().debug("     • Total BARs in session: %zu", bars.size());
}

//------------------------------------------------------------------------------
// create_bar — 3GPP TS 29.244 Table 7.5.2.6-1
// Mandatory IE: BAR ID

//------------------------------------------------------------------------------
bool pfcp_session::create(
    const pfcp::create_bar& cr_bar, pfcp::cause_t& cause,
    uint16_t& offending_ie) {
  if (not cr_bar.bar_id.first) {
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie      = PFCP_IE_BAR_ID;
    return false;
  }
  auto bar = std::make_shared<pfcp::pfcp_bar>(cr_bar);
  add(bar);
  cause.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
  return true;
}

//------------------------------------------------------------------------------
// update_bar — 3GPP TS 29.244 Table 7.5.4.11-1
// Delegates to pfcp_bar::update() which handles the type conversion between
// pfcp::downlink_data_notification_delay_t → bar_dl_delay_t and
// pfcp::suggested_buffering_packets_count_t → bar_buffering_count_t.

//------------------------------------------------------------------------------
bool pfcp_session::update(
    const pfcp::update_bar_within_pfcp_session_modification_request& bar_update,
    uint8_t& cause_value) {
  if (not bar_update.bar_id.first) {
    cause_value = CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE;
    return false;
  }
  uint8_t bar_id = bar_update.bar_id.second.bar_id;
  Logger::upf_n4().info(
      "pfcp_session::update(bar) seid " SEID_FMT " BAR=%u", seid, bar_id);
  for (auto& existing : bars) {
    if (existing->bar_id.second.bar_id == bar_id) {
      // Field-by-field conversion required: pair assignment is not possible
      // because the stored types differ from the PFCP wire types.
      // V17.10.0 §-refs: BAR ID §8.2.57, SugBuffPktCnt §8.2.100.

      // §8.2.28 — Downlink Data Notification Delay (Sxa + N4 in Update BAR)
      if (bar_update.downlink_data_notification_delay.first) {
        existing->downlink_data_notification_delay.first = true;
        existing->downlink_data_notification_delay.second.delay_value =
            bar_update.downlink_data_notification_delay.second.delay;  // ×50 ms
      }
      // §8.2.100 — Suggested Buffering Packets Count (Sxb + Sxc + N4)
      if (bar_update.suggested_buffering_packets_count.first) {
        existing->suggested_buffering_packets_count.first = true;
        existing->suggested_buffering_packets_count.second.packet_count =
            bar_update.suggested_buffering_packets_count.second
                .packets_count_value;
      }
      // §8.2.29 DL Buffering Duration and §8.2.30 DL Buffering Suggested
      // Packet Count: not in update_bar_within_pfcp_session_modification_
      // request (lib gap). Handled via pfcp_bar::update(report_response).
      Logger::upf_n4().info(
          "  └─ Updated BAR %u in session " SEID_FMT, bar_id, seid);
      cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
      return true;
    }
  }
  Logger::upf_n4().warn(
      "  └─ BAR %u not found in session " SEID_FMT " - cannot update", bar_id,
      seid);
  cause_value = CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE;
  return false;
}

//------------------------------------------------------------------------------
// remove_bar — 3GPP TS 29.244 Table 7.5.4.12-1

//------------------------------------------------------------------------------
bool pfcp_session::remove(
    const pfcp::remove_bar& rm_bar, pfcp::cause_t& cause,
    uint16_t& offending_ie) {
  if (not rm_bar.bar_id.first) {
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie      = PFCP_IE_BAR_ID;
    return false;
  }
  uint8_t bar_id = rm_bar.bar_id.second.bar_id;
  Logger::upf_n4().info(
      "pfcp_session::remove(bar) seid " SEID_FMT " BAR=%u", seid, bar_id);
  for (auto it = bars.begin(); it != bars.end(); ++it) {
    if ((*it)->bar_id.second.bar_id == bar_id) {
      bars.erase(it);
      Logger::upf_n4().info(
          "  └─ Removed BAR %u from session " SEID_FMT " (%zu BARs remaining)",
          bar_id, seid, bars.size());
      cause.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
      return true;
    }
  }
  Logger::upf_n4().warn(
      "  └─ BAR %u not found in session " SEID_FMT " - cannot remove", bar_id,
      seid);
  cause.cause_value = CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE;
  offending_ie      = PFCP_IE_BAR_ID;
  return false;
}

// =============================================================================
// MAR — add / create / update / remove
// =============================================================================

//------------------------------------------------------------------------------
void pfcp_session::add(std::shared_ptr<pfcp::pfcp_mar> mar) {
  uint8_t mar_id = mar->mar_id.second.mar_id;
  Logger::upf_n4().info(
      "pfcp_session::add(mar) seid " SEID_FMT " MAR=%u", seid, mar_id);
  for (auto it = mars.begin(); it != mars.end(); ++it) {
    if ((*it)->mar_id.second.mar_id == mar_id) {
      Logger::upf_n4().info(
          "  └─ Replacing existing MAR %u in session " SEID_FMT, mar_id, seid);
      *it = mar;
      return;
    }
  }
  Logger::upf_n4().info(
      "  └─ Adding new MAR %u to session " SEID_FMT, mar_id, seid);
  mars.push_back(mar);
  Logger::upf_n4().debug("     • Total MARs in session: %zu", mars.size());
}

//------------------------------------------------------------------------------
// create_mar — 3GPP TS 29.244 V17.10.0 Table 7.5.2.8-1
// Mandatory IE: MAR ID §8.2.123. Converts access_forwarding_action_information
// (IE types 166/167) → mar_access_forwarding_action_t field-by-field.
// TODO V17.10.0: Thresholds (§8.2.196) and Steering Mode Indicator (§8.2.197)
// are not yet in the OAI lib's create_mar — add when lib is updated.

//------------------------------------------------------------------------------
bool pfcp_session::create(
    const pfcp::create_mar& cr_mar, pfcp::cause_t& cause,
    uint16_t& offending_ie) {
  if (not cr_mar.mar_id.first) {
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie      = PFCP_IE_MAR_ID;
    return false;
  }
  auto mar    = std::make_shared<pfcp::pfcp_mar>();
  mar->mar_id = cr_mar.mar_id;
  if (cr_mar.steering_functionality.first)
    mar->steering_functionality = cr_mar.steering_functionality;
  if (cr_mar.steering_mode.first) mar->steering_mode = cr_mar.steering_mode;

  // Convert access_forwarding_action_information →
  // mar_access_forwarding_action_t
  if (cr_mar.access_forwarding_action_information_1.first) {
    const auto& afai = cr_mar.access_forwarding_action_information_1.second;
    pfcp::mar_access_forwarding_action_t dst{};
    pfcp::far_id_t far_val;
    if (afai.get(far_val)) dst.far_id = far_val;
    pfcp::urr_id_t urr_val;
    if (afai.get(urr_val)) {
      dst.urr_id         = urr_val;
      dst.urr_id_present = true;
    }
    if (afai.weight.first) {
      dst.weight.weight_value = afai.weight.second;
      dst.weight_present      = true;  // §8.2.126 — Load Balancing mode
    }
    if (afai.priority.first) {
      dst.priority.priority_value = afai.priority.second;
      dst.priority_present = true;  // §8.2.127 — Active-Standby/Priority-based
    }
    // TODO V17.10.0: RAT Type (O, §8.2.186) — not yet in lib's AFAI type.
    mar->access_forwarding_action_info_1 = {true, dst};
  }
  if (cr_mar.access_forwarding_action_information_2.first) {
    const auto& afai = cr_mar.access_forwarding_action_information_2.second;
    pfcp::mar_access_forwarding_action_t dst{};
    pfcp::far_id_t far_val;
    if (afai.get(far_val)) dst.far_id = far_val;
    pfcp::urr_id_t urr_val;
    if (afai.get(urr_val)) {
      dst.urr_id         = urr_val;
      dst.urr_id_present = true;
    }
    if (afai.weight.first) {
      dst.weight.weight_value = afai.weight.second;
      dst.weight_present      = true;  // §8.2.126 — Load Balancing mode
    }
    if (afai.priority.first) {
      dst.priority.priority_value = afai.priority.second;
      dst.priority_present = true;  // §8.2.127 — Active-Standby/Priority-based
    }
    // TODO V17.10.0: RAT Type (O, §8.2.186) — not yet in lib's AFAI type.
    mar->access_forwarding_action_info_2 = {true, dst};
  }
  add(mar);
  cause.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
  return true;
}

//------------------------------------------------------------------------------
// update_mar — 3GPP TS 29.244 Table 7.5.4.16-1
// Reuses the same AFAI conversion lambda as create_mar.

//------------------------------------------------------------------------------
bool pfcp_session::update(
    const pfcp::update_mar& mar_update, uint8_t& cause_value) {
  if (not mar_update.mar_id.first) {
    cause_value = CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE;
    return false;
  }
  uint8_t mar_id = mar_update.mar_id.second.mar_id;
  Logger::upf_n4().info(
      "pfcp_session::update(mar) seid " SEID_FMT " MAR=%u", seid, mar_id);
  for (auto& existing : mars) {
    if (existing->mar_id.second.mar_id == mar_id) {
      if (mar_update.steering_functionality.first)
        existing->steering_functionality = mar_update.steering_functionality;
      if (mar_update.steering_mode.first)
        existing->steering_mode = mar_update.steering_mode;

      // AFAI field-by-field conversion (access_forwarding_action_information
      // IE types 166/167 → mar_access_forwarding_action_t).
      // TODO V17.10.0: Update 3GPP/Non-3GPP AFAI (IE types 175/176,
      // Tables 7.5.4.16-2/3) not yet in lib — handled as full replace for now.
      // TODO V17.10.0: Thresholds (§8.2.196) and Steering Mode Indicator
      // (§8.2.197) not yet in lib's update_mar — add when lib is updated.
      auto convert_afai =
          [](const pfcp::access_forwarding_action_information& afai,
             std::pair<bool, pfcp::mar_access_forwarding_action_t>& dst_pair) {
            pfcp::mar_access_forwarding_action_t dst{};
            pfcp::far_id_t far_val;
            if (afai.get(far_val)) dst.far_id = far_val;
            pfcp::urr_id_t urr_val;
            if (afai.get(urr_val)) {
              dst.urr_id         = urr_val;
              dst.urr_id_present = true;
            }
            if (afai.weight.first) {
              dst.weight.weight_value = afai.weight.second;
              dst.weight_present = true;  // §8.2.126 — Load Balancing mode
            }
            if (afai.priority.first) {
              dst.priority.priority_value = afai.priority.second;
              dst.priority_present =
                  true;  // §8.2.127 — Active-Standby/Priority-based
            }
            // TODO V17.10.0: RAT Type (O, §8.2.186) — not yet in lib's AFAI
            // type.
            dst_pair = {true, dst};
          };

      pfcp::access_forwarding_action_information afai;
      if (mar_update.get_access_forwarding_action_information_1(afai))
        convert_afai(afai, existing->access_forwarding_action_info_1);
      if (mar_update.get_access_forwarding_action_information_2(afai))
        convert_afai(afai, existing->access_forwarding_action_info_2);

      Logger::upf_n4().info(
          "  └─ Updated MAR %u in session " SEID_FMT, mar_id, seid);
      cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
      return true;
    }
  }
  Logger::upf_n4().warn(
      "  └─ MAR %u not found in session " SEID_FMT " - cannot update", mar_id,
      seid);
  cause_value = CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE;
  return false;
}

//------------------------------------------------------------------------------
// remove_mar — 3GPP TS 29.244 V17.10.0 Table 7.5.4.15-1

//------------------------------------------------------------------------------
bool pfcp_session::remove(
    const pfcp::remove_mar& rm_mar, pfcp::cause_t& cause,
    uint16_t& offending_ie) {
  if (not rm_mar.mar_id.first) {
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie      = PFCP_IE_MAR_ID;
    return false;
  }
  uint8_t mar_id = rm_mar.mar_id.second.mar_id;
  Logger::upf_n4().info(
      "pfcp_session::remove(mar) seid " SEID_FMT " MAR=%u", seid, mar_id);
  for (auto it = mars.begin(); it != mars.end(); ++it) {
    if ((*it)->mar_id.second.mar_id == mar_id) {
      mars.erase(it);
      Logger::upf_n4().info(
          "  └─ Removed MAR %u from session " SEID_FMT " (%zu MARs remaining)",
          mar_id, seid, mars.size());
      cause.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
      return true;
    }
  }
  Logger::upf_n4().warn(
      "  └─ MAR %u not found in session " SEID_FMT " - cannot remove", mar_id,
      seid);
  cause.cause_value = CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE;
  offending_ie      = PFCP_IE_MAR_ID;
  return false;
}

// =============================================================================
// PDR — update / remove / create
// =============================================================================

//------------------------------------------------------------------------------
// update_pdr — 3GPP TS 29.244 Table 7.5.4.2-1

//------------------------------------------------------------------------------
bool pfcp_session::update(
    const pfcp::update_pdr& pdr_update, uint8_t& cause_value) {
  uint16_t pdr_id = pdr_update.pdr_id.rule_id;

  Logger::upf_n4().info(
      "pfcp_session::update(pdr) seid " SEID_FMT " PDR=%u", seid, pdr_id);

  // Find the PDR to update
  for (auto& existing_pdr : pdrs) {
    if (existing_pdr->pdr_id.rule_id == pdr_id) {
      Logger::upf_n4().info(
          "  └─ Updating PDR %u in session " SEID_FMT, pdr_id, seid);

      // Track what changed
      bool has_changes = false;

      // Update FAR ID
      if (pdr_update.far_id.first) {
        uint32_t old_far =
            existing_pdr->far_id.first ? existing_pdr->far_id.second.far_id : 0;
        uint32_t new_far = pdr_update.far_id.second.far_id;

        if (old_far != new_far) {
          Logger::upf_n4().debug("     • FAR ID: %u → %u", old_far, new_far);
          has_changes = true;
        }
        existing_pdr->far_id = pdr_update.far_id;
      }

      // Update QER ID
      if (pdr_update.qer_id.first) {
        uint32_t old_qer =
            existing_pdr->qer_id.first ? existing_pdr->qer_id.second.qer_id : 0;
        uint32_t new_qer = pdr_update.qer_id.second.qer_id;

        if (old_qer != new_qer) {
          Logger::upf_n4().debug("     • QER ID: %u → %u", old_qer, new_qer);
          has_changes = true;
        }
        existing_pdr->qer_id = pdr_update.qer_id;
      }

      // Update precedence
      if (pdr_update.precedence.first) {
        uint32_t old_prec = existing_pdr->precedence.first ?
                                existing_pdr->precedence.second.precedence :
                                0;
        uint32_t new_prec = pdr_update.precedence.second.precedence;

        if (old_prec != new_prec) {
          Logger::upf_n4().debug(
              "     • Precedence: %u → %u", old_prec, new_prec);
          has_changes = true;
        }
        existing_pdr->precedence = pdr_update.precedence;
      }

      // Update PDI (Packet Detection Information)
      if (pdr_update.pdi.first) {
        Logger::upf_n4().debug("     • Updated PDI");
        existing_pdr->pdi = pdr_update.pdi;
        has_changes       = true;
      }

      if (!has_changes) {
        Logger::upf_n4().debug("     • No actual changes detected");
      }

      cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
      return true;
    }
  }

  // PDR not found
  Logger::upf_n4().warn(
      "  └─ PDR %u not found in session " SEID_FMT " - cannot update", pdr_id,
      seid);

  cause_value = CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE;
  return false;
}

//------------------------------------------------------------------------------
// remove_pdr — 3GPP TS 29.244 Table 7.5.4.6-1

//------------------------------------------------------------------------------
bool pfcp_session::remove(
    const pfcp::remove_pdr& pdr_removal, pfcp::cause_t& cause,
    uint16_t& offending_ie) {
  if (not pdr_removal.pdr_id.first) {
    // should be caught in lower layer
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie      = PFCP_IE_PACKET_DETECTION_RULE_ID;
    return false;
  }

  uint16_t pdr_id = pdr_removal.pdr_id.second.rule_id;

  Logger::upf_n4().info(
      "pfcp_session::remove(pdr) seid " SEID_FMT " PDR=%u", seid, pdr_id);

  // Find and remove the PDR
  for (auto it = pdrs.begin(); it != pdrs.end(); ++it) {
    if ((*it)->pdr_id.rule_id == pdr_id) {
      // Log details before removal
      Logger::upf_n4().info(
          "  └─ Removing PDR %u from session " SEID_FMT, pdr_id, seid);

      // Show what we're removing
      if ((*it)->pdi.first && (*it)->pdi.second.source_interface.first) {
        uint8_t iface =
            (*it)->pdi.second.source_interface.second.interface_value;
        const char* dir = (iface == INTERFACE_VALUE_ACCESS) ? "Uplink" :
                          (iface == INTERFACE_VALUE_CORE)   ? "Downlink" :
                                                              "Unknown";
        Logger::upf_n4().debug("     • Direction: %s", dir);
      }

      if ((*it)->far_id.first) {
        Logger::upf_n4().debug(
            "     • Was linked to FAR %u", (*it)->far_id.second.far_id);
      }

      if ((*it)->qer_id.first) {
        Logger::upf_n4().debug(
            "     • Was linked to QER %u", (*it)->qer_id.second.qer_id);
      }

      // Remove the PDR
      pdrs.erase(it);
      Logger::upf_n4().debug("     • Total PDRs remaining: %zu", pdrs.size());

      cause.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
      return true;
    }
  }

  // PDR not found
  Logger::upf_n4().warn(
      "  └─ PDR %u not found in session " SEID_FMT " - cannot remove", pdr_id,
      seid);

  cause.cause_value = CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE;
  offending_ie      = PFCP_IE_PACKET_DETECTION_RULE_ID;
  return false;
}

// =============================================================================
// FAR — update / remove / create
// =============================================================================

//------------------------------------------------------------------------------
// update_far — 3GPP TS 29.244 Table 7.5.4.3-1

//------------------------------------------------------------------------------
bool pfcp_session::update(
    const pfcp::update_far& far_update, uint8_t& cause_value) {
  uint32_t far_id = far_update.far_id.far_id;

  Logger::upf_n4().info(
      "pfcp_session::update(far) seid " SEID_FMT " FAR=%u", seid, far_id);

  // Find the FAR to update
  for (auto& existing_far : fars) {
    if (existing_far->far_id.far_id == far_id) {
      Logger::upf_n4().info(
          "  └─ Updating FAR %u in session " SEID_FMT, far_id, seid);

      bool has_changes = false;

      // Update apply action
      if (far_update.apply_action.first) {
        std::ostringstream old_actions, new_actions;

        // Old actions
        if (existing_far->apply_action.forw) old_actions << "FORW ";
        if (existing_far->apply_action.drop) old_actions << "DROP ";
        if (existing_far->apply_action.buff) old_actions << "BUFF ";
        if (existing_far->apply_action.nocp) old_actions << "NOCP";

        // New actions
        if (far_update.apply_action.second.forw) new_actions << "FORW ";
        if (far_update.apply_action.second.drop) new_actions << "DROP ";
        if (far_update.apply_action.second.buff) new_actions << "BUFF ";
        if (far_update.apply_action.second.nocp) new_actions << "NOCP";

        if (old_actions.str() != new_actions.str()) {
          Logger::upf_n4().debug(
              "     • Apply Action: %s → %s", old_actions.str().c_str(),
              new_actions.str().c_str());
          has_changes = true;
        }

        existing_far->apply_action = far_update.apply_action.second;
      }

      if (far_update.update_forwarding_parameters.first) {
        auto& new_params = far_update.update_forwarding_parameters.second;

        // Update destination interface
        if (new_params.destination_interface.first) {
          uint8_t old_iface =
              existing_far->forwarding_parameters.first ?
                  existing_far->forwarding_parameters.second
                      .destination_interface.second.interface_value :
                  0;
          uint8_t new_iface =
              new_params.destination_interface.second.interface_value;

          if (old_iface != new_iface) {
            const char* old_str =
                (old_iface == INTERFACE_VALUE_ACCESS) ? "ACCESS" :
                (old_iface == INTERFACE_VALUE_CORE)   ? "CORE" :
                                                        "UNKNOWN";
            const char* new_str =
                (new_iface == INTERFACE_VALUE_ACCESS) ? "ACCESS" :
                (new_iface == INTERFACE_VALUE_CORE)   ? "CORE" :
                                                        "UNKNOWN";
            Logger::upf_n4().debug(
                "     • Destination: %s → %s", old_str, new_str);
            has_changes = true;
          }

          // Copy destination interface
          existing_far->forwarding_parameters.first = true;
          existing_far->forwarding_parameters.second.destination_interface =
              new_params.destination_interface;
        }

        // Update outer header (TEID)
        if (new_params.outer_header_creation.first) {
          uint32_t old_teid = (existing_far->forwarding_parameters.first &&
                               existing_far->forwarding_parameters.second
                                   .outer_header_creation.first) ?
                                  existing_far->forwarding_parameters.second
                                      .outer_header_creation.second.teid :
                                  0;
          uint32_t new_teid = new_params.outer_header_creation.second.teid;

          if (old_teid != new_teid) {
            Logger::upf_n4().debug(
                "     • Outer Header TEID: 0x%x → 0x%x", old_teid, new_teid);
            has_changes = true;

            // Log new IP if present
            if (new_params.outer_header_creation.second
                    .outer_header_creation_description ==
                OUTER_HEADER_CREATION_GTPU_UDP_IPV4) {
              char ip_str[INET_ADDRSTRLEN];
              inet_ntop(
                  AF_INET,
                  &new_params.outer_header_creation.second.ipv4_address, ip_str,
                  INET_ADDRSTRLEN);
              Logger::upf_n4().debug("     • New Remote IP: %s", ip_str);
            }
          }

          // Copy outer header creation
          existing_far->forwarding_parameters.first = true;
          existing_far->forwarding_parameters.second.outer_header_creation =
              new_params.outer_header_creation;
        }

        // Copy network instance if present
        if (new_params.network_instance.first) {
          existing_far->forwarding_parameters.second.network_instance =
              new_params.network_instance;
        }
      }

      if (!has_changes) {
        Logger::upf_n4().debug("     • No actual changes detected");
      }

      cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
      return true;
    }
  }

  // FAR not found
  Logger::upf_n4().warn(
      "  └─ FAR %u not found in session " SEID_FMT " - cannot update", far_id,
      seid);

  cause_value = CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE;
  return false;
}

//------------------------------------------------------------------------------
// remove_far — 3GPP TS 29.244 Table 7.5.4.7-1

//------------------------------------------------------------------------------
bool pfcp_session::remove(
    const pfcp::remove_far& far_removal, pfcp::cause_t& cause,
    uint16_t& offending_ie) {
  if (not far_removal.far_id.first) {
    // should be caught in lower layer
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie      = PFCP_IE_FAR_ID;
    return false;
  }

  uint32_t far_id = far_removal.far_id.second.far_id;

  Logger::upf_n4().info(
      "pfcp_session::remove(far) seid " SEID_FMT " FAR=%u", seid, far_id);

  // Find and remove the FAR
  for (auto it = fars.begin(); it != fars.end(); ++it) {
    if ((*it)->far_id.far_id == far_id) {
      // Log details before removal
      Logger::upf_n4().info(
          "  └─ Removing FAR %u from session " SEID_FMT, far_id, seid);

      // Show apply action
      if ((*it)->apply_action.forw || (*it)->apply_action.drop ||
          (*it)->apply_action.buff || (*it)->apply_action.nocp) {
        std::ostringstream actions;
        if ((*it)->apply_action.forw) actions << "FORW ";
        if ((*it)->apply_action.drop) actions << "DROP ";
        if ((*it)->apply_action.buff) actions << "BUFF ";
        if ((*it)->apply_action.nocp) actions << "NOCP";
        Logger::upf_n4().debug("     • Had Action: %s", actions.str().c_str());
      }

      // Show destination
      if ((*it)->forwarding_parameters.first &&
          (*it)->forwarding_parameters.second.destination_interface.first) {
        uint8_t iface = (*it)
                            ->forwarding_parameters.second.destination_interface
                            .second.interface_value;
        const char* dest = (iface == INTERFACE_VALUE_ACCESS) ? "ACCESS" :
                           (iface == INTERFACE_VALUE_CORE)   ? "CORE" :
                                                               "UNKNOWN";
        Logger::upf_n4().debug("     • Destination: %s", dest);
      }

      // Remove the FAR
      fars.erase(it);
      Logger::upf_n4().debug("     • Total FARs remaining: %zu", fars.size());

      cause.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
      return true;
    }
  }

  // FAR not found
  Logger::upf_n4().warn(
      "  └─ FAR %u not found in session " SEID_FMT " - cannot remove", far_id,
      seid);

  cause.cause_value = CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE;
  offending_ie      = PFCP_IE_FAR_ID;
  return false;
}

//------------------------------------------------------------------------------
// create_far — 3GPP TS 29.244 Table 7.5.2.3-1

//------------------------------------------------------------------------------
bool pfcp_session::create(
    const pfcp::create_far& cr_far, pfcp::cause_t& cause,
    uint16_t& offending_ie) {
  if (not cr_far.far_id.first) {
    // should be caught in lower layer
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie      = PFCP_IE_FAR_ID;
    return false;
  }
  if (not cr_far.apply_action.first) {
    // should be caught in lower layer
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie      = PFCP_IE_APPLY_ACTION;
    return false;
  }
  if (cr_far.apply_action.second.forw) {
    if (not cr_far.forwarding_parameters.first) {
      // should be caught in lower layer
      cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
      offending_ie      = PFCP_IE_FORWARDING_PARAMETERS;
      return false;
    }
  }
  if (cr_far.apply_action.second.dupl) {
    if (not cr_far.duplicating_parameters.first) {
      // should be caught in lower layer
      cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
      offending_ie      = PFCP_IE_DUPLICATING_PARAMETERS;
      return false;
    }
  }
  pfcp_far* far                  = new pfcp_far(cr_far);
  std::shared_ptr<pfcp_far> sfar = std::shared_ptr<pfcp_far>(far);
  add(sfar);
  cause.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
  return true;
}

// =============================================================================
// QER — update / remove / create
// =============================================================================

//------------------------------------------------------------------------------
// update_qer — 3GPP TS 29.244 V17.10.0 Table 7.5.4.5-1
// Covers all IEs delegated to pfcp_qer::update() after logging old→new.
// Field assignments are NOT repeated here; pfcp_qer::update() owns them.

//------------------------------------------------------------------------------
bool pfcp_session::update(
    const pfcp::update_qer& qer_update, uint8_t& cause_value) {
  uint32_t qer_id = qer_update.qer_id.qer_id;

  Logger::upf_n4().info(
      "pfcp_session::update(qer) seid " SEID_FMT " QER=%u", seid, qer_id);

  // Find the QER to update
  for (auto& existing_qer : qers) {
    if (existing_qer->qer_id.second.qer_id == qer_id) {
      Logger::upf_n4().info(
          "  └─ Updating QER %u in session " SEID_FMT, qer_id, seid);

      bool has_changes = false;

      // Gate Status (§8.2.7)
      if (qer_update.gate_status.first) {
        const char* old_ul =
            (existing_qer->gate_status.first &&
             existing_qer->gate_status.second.ul_gate == PFCP_GATE_OPEN) ?
                "OPEN" :
                "CLOSED";
        const char* old_dl =
            (existing_qer->gate_status.first &&
             existing_qer->gate_status.second.dl_gate == PFCP_GATE_OPEN) ?
                "OPEN" :
                "CLOSED";
        const char* new_ul =
            (qer_update.gate_status.second.ul_gate == PFCP_GATE_OPEN) ?
                "OPEN" :
                "CLOSED";
        const char* new_dl =
            (qer_update.gate_status.second.dl_gate == PFCP_GATE_OPEN) ?
                "OPEN" :
                "CLOSED";

        if (strcmp(old_ul, new_ul) != 0 || strcmp(old_dl, new_dl) != 0) {
          Logger::upf_n4().debug(
              "     • Gate Status: UL=%s→%s, DL=%s→%s", old_ul, new_ul, old_dl,
              new_dl);
          has_changes = true;
        }
      }

      // GBR (§8.2.9) — log both UL and DL
      if (qer_update.guaranteed_bitrate.first) {
        uint64_t old_ul_gbr =
            existing_qer->guaranteed_bitrate.first ?
                existing_qer->guaranteed_bitrate.second.ul_gbr :
                0;
        uint64_t old_dl_gbr =
            existing_qer->guaranteed_bitrate.first ?
                existing_qer->guaranteed_bitrate.second.dl_gbr :
                0;
        uint64_t new_ul_gbr = qer_update.guaranteed_bitrate.second.ul_gbr;
        uint64_t new_dl_gbr = qer_update.guaranteed_bitrate.second.dl_gbr;

        if (old_ul_gbr != new_ul_gbr || old_dl_gbr != new_dl_gbr) {
          Logger::upf_n4().debug(
              "     • GBR: UL: %llu → %llu kbps, DL: %llu → %llu kbps",
              old_ul_gbr, new_ul_gbr, old_dl_gbr, new_dl_gbr);
          has_changes = true;
        }
      }

      // MBR (§8.2.8) — log both UL and DL
      if (qer_update.maximum_bitrate.first) {
        uint64_t old_ul_mbr = existing_qer->maximum_bitrate.first ?
                                  existing_qer->maximum_bitrate.second.ul_mbr :
                                  0;
        uint64_t old_dl_mbr = existing_qer->maximum_bitrate.first ?
                                  existing_qer->maximum_bitrate.second.dl_mbr :
                                  0;
        uint64_t new_ul_mbr = qer_update.maximum_bitrate.second.ul_mbr;
        uint64_t new_dl_mbr = qer_update.maximum_bitrate.second.dl_mbr;

        if (old_ul_mbr != new_ul_mbr || old_dl_mbr != new_dl_mbr) {
          Logger::upf_n4().debug(
              "     • MBR: UL: %llu → %llu kbps, DL: %llu → %llu kbps",
              old_ul_mbr, new_ul_mbr, old_dl_mbr, new_dl_mbr);
          has_changes = true;
        }
      }

      // QFI (§8.2.89)
      if (qer_update.qos_flow_identifier.first) {
        uint8_t old_qfi = existing_qer->qos_flow_id.first ?
                              existing_qer->qos_flow_id.second.qfi :
                              0;
        uint8_t new_qfi = qer_update.qos_flow_identifier.second.qfi;

        if (old_qfi != new_qfi) {
          Logger::upf_n4().debug("     • QFI: %u → %u", old_qfi, new_qfi);
          has_changes = true;
        }
      }

      // QER Correlation ID (§8.2.10)
      if (qer_update.qer_correlation_id.first) {
        uint32_t old_corr =
            existing_qer->qer_correlation_id.first ?
                existing_qer->qer_correlation_id.second.qer_correlation_id :
                0;
        uint32_t new_corr =
            qer_update.qer_correlation_id.second.qer_correlation_id;

        if (old_corr != new_corr) {
          Logger::upf_n4().debug(
              "     • QER Correlation ID: %u → %u", old_corr, new_corr);
          has_changes = true;
        }
      }

      // Reflective QoS (§8.2.88)
      if (qer_update.reflective_qos.first) {
        bool old_rqi = existing_qer->reflective_qos.first &&
                       existing_qer->reflective_qos.second.rqi;
        bool new_rqi = qer_update.reflective_qos.second.rqi;

        if (old_rqi != new_rqi) {
          Logger::upf_n4().debug(
              "     • Reflective QoS: %s → %s",
              old_rqi ? "Enabled" : "Disabled",
              new_rqi ? "Enabled" : "Disabled");
          has_changes = true;
        }
      }

      // Paging Policy Indicator (§8.2.116)
      if (qer_update.paging_policy_indicator.first) {
        uint8_t old_ppi =
            existing_qer->paging_policy_indicator.first ?
                existing_qer->paging_policy_indicator.second.ppi_value :
                0;
        uint8_t new_ppi = qer_update.paging_policy_indicator.second.ppi_value;

        if (old_ppi != new_ppi) {
          Logger::upf_n4().debug(
              "     • Paging Policy Indicator: %u → %u", old_ppi, new_ppi);
          has_changes = true;
        }
      }

      // Averaging Window (§8.2.115)
      if (qer_update.averaging_window.first) {
        uint32_t old_win =
            existing_qer->averaging_window.first ?
                existing_qer->averaging_window.second.averaging_window :
                0;
        uint32_t new_win = qer_update.averaging_window.second.averaging_window;

        if (old_win != new_win) {
          Logger::upf_n4().debug(
              "     • Averaging Window: %u → %u ms", old_win, new_win);
          has_changes = true;
        }
      }

      if (!has_changes) {
        Logger::upf_n4().debug("     • No actual changes detected");
      }

      // Delegate all field assignments to pfcp_qer::update() — single source
      // of truth for the IE-to-field mapping (Table 7.5.4.5-1).
      existing_qer->update(qer_update, cause_value);
      cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
      return true;
    }
  }

  // QER not found
  Logger::upf_n4().warn(
      "  └─ QER %u not found in session " SEID_FMT " - cannot update", qer_id,
      seid);

  cause_value = CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE;
  return false;
}

//------------------------------------------------------------------------------
// remove_qer — 3GPP TS 29.244 Table 7.5.4.9-1

//------------------------------------------------------------------------------
bool pfcp_session::remove(
    const pfcp::remove_qer& qer_removal, pfcp::cause_t& cause,
    uint16_t& offending_ie) {
  if (not qer_removal.qer_id.first) {
    // should be caught in lower layer
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie      = PFCP_IE_QER_ID;
    return false;
  }

  uint32_t qer_id = qer_removal.qer_id.second.qer_id;

  Logger::upf_n4().info(
      "pfcp_session::remove(qer) seid " SEID_FMT " QER=%u", seid, qer_id);

  // Find and remove the QER
  for (auto it = qers.begin(); it != qers.end(); ++it) {
    if ((*it)->qer_id.second.qer_id == qer_id) {
      // Log details before removal
      Logger::upf_n4().info(
          "  └─ Removing QER %u from session " SEID_FMT, qer_id, seid);

      // Show QFI
      if ((*it)->qos_flow_id.first) {
        Logger::upf_n4().debug("     • QFI: %u", (*it)->qos_flow_id.second.qfi);
      }

      // Show GBR/MBR if present
      if ((*it)->guaranteed_bitrate.first) {
        Logger::upf_n4().debug(
            "     • Had GBR: %llu kbps (DL)",
            (*it)->guaranteed_bitrate.second.dl_gbr / 1000);
      }

      if ((*it)->maximum_bitrate.first) {
        Logger::upf_n4().debug(
            "     • Had MBR: %llu kbps (DL)",
            (*it)->maximum_bitrate.second.dl_mbr / 1000);
      }

      // Remove the QER
      qers.erase(it);
      Logger::upf_n4().debug("     • Total QERs remaining: %zu", qers.size());

      cause.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
      return true;
    }
  }

  // QER not found
  Logger::upf_n4().warn(
      "  └─ QER %u not found in session " SEID_FMT " - cannot remove", qer_id,
      seid);

  cause.cause_value = CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE;
  offending_ie      = PFCP_IE_QER_ID;
  return false;
}

//------------------------------------------------------------------------------
// create_pdr — 3GPP TS 29.244 Table 7.5.2.2-1
// Allocates an F-TEID for ACCESS PDRs (uplink).

//------------------------------------------------------------------------------
bool pfcp_session::create(
    const pfcp::create_pdr& cr_pdr, pfcp::cause_t& cause,
    uint16_t& offending_ie, pfcp::fteid_t& allocated_fteid) {
  if (not cr_pdr.pdr_id.first) {
    // should be caught in lower layer
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie      = PFCP_IE_PACKET_DETECTION_RULE_ID;
    return false;
  }
  if (not cr_pdr.pdi.first) {
    // should be caught in lower layer
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie      = PFCP_IE_PDI;
    return false;
  }
  if (not cr_pdr.precedence.first) {
    // should be caught in lower layer
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie      = PFCP_IE_PRECEDENCE;
    return false;
  }
  const pdi& pdi = cr_pdr.pdi.second;
  if (not pdi.source_interface.first) {
    // should be caught in lower layer
    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie      = PFCP_IE_SOURCE_INTERFACE;
    return false;
  }
  // already checked but !!! keep this code in comment !!!
  //  pfcp::far_id_t    far_id = {};
  //  if (not cr_pdr.get(far_id)) {
  //    //should be caught in lower layer
  //    cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
  //    offending_ie = PFCP_IE_FAR_ID;
  //    return false;
  //  }

  if (pdi.traffic_endpoint_id.first) {
    cause.cause_value = CAUSE_VALUE_REQUEST_REJECTED;
    Logger::upf_n4().info("Do not support IE traffic_endpoint_id yet!");
    return false;
  }

  // source interface of the incoming packet
  if (pdi.source_interface.second.interface_value == INTERFACE_VALUE_ACCESS ||
      pdi.source_interface.second.interface_value ==
          INTERFACE_VALUE_CP_FUNCTION) {
    // Uplink — must have a local F-TEID (§8.2.3); allocate or use CP value
    if (not pdi.local_fteid.first) {
      cause.cause_value = CAUSE_VALUE_MANDATORY_IE_MISSING;
      offending_ie      = PFCP_IE_F_TEID;
      return false;
    }
    const pfcp::fteid_t& local_fteid = pdi.local_fteid.second;
    allocated_fteid                  = {};
    if (local_fteid.ch) {
      // TODO if (local_fteid.choose_id) {
      allocated_fteid = pfcp_switch_inst->generate_fteid_n3();
    } else {
      // cause.cause_value = CAUSE_VALUE_REQUEST_REJECTED;
      allocated_fteid = pdi.local_fteid.second;
      /*Logger::upf_n4().info(
          "Do not support IE FTEID managed by CP entity! Rejecting "
          "PFCP_XXX_REQUEST");
          */
      Logger::upf_n4().info(
          "TEID " TEID_FMT " received from CP", allocated_fteid.teid);
      // return false;
    }
    pfcp_pdr* pdr = new pfcp_pdr(cr_pdr);
    if (local_fteid.ch) {
      pdr->pdi.second.set(allocated_fteid);
    }

    set(allocated_fteid);

    // Check if s_allocated_fteid is set
    pfcp::fteid_t fteid;
    if (!get(fteid)) {
      cause.cause_value = CAUSE_VALUE_REQUEST_REJECTED;
      Logger::upf_n4().info("TEID is not set in pfcp_session::create");
      return false;
    }

    std::shared_ptr<pfcp_pdr> spdr = std::shared_ptr<pfcp_pdr>(pdr);
    if (pfcp_switch_inst->create_packet_in_access(
            spdr, allocated_fteid, cause.cause_value)) {
      pdr->set(get_up_seid());
      add(spdr);
    } else {
      cause.cause_value = CAUSE_VALUE_REQUEST_REJECTED;
      Logger::upf_n4().info(
          "Could not create_packet_in_access ! Rejecting "
          "PFCP_SESSION_ESTABLISHMENT_REQUEST");
      return false;
    }
  } else if (
      pdi.source_interface.second.interface_value == INTERFACE_VALUE_CORE) {
    // Downlink — register by UE IP for core-to-UE forwarding
    pfcp_pdr* pdr                  = new pfcp_pdr(cr_pdr);
    std::shared_ptr<pfcp_pdr> spdr = std::shared_ptr<pfcp_pdr>(pdr);
    pdr->set(get_up_seid());
    if ((pdi.ue_ip_address.first) && (pdi.ue_ip_address.second.v4)) {
      pfcp_switch_inst->add_pfcp_dl_pdr_by_ue_ip(
          be32toh(pdi.ue_ip_address.second.ipv4_address.s_addr), spdr);
    } else if (pdi.ethernet_pdu_session_information.first) {
      Logger::upf_n4().info(
          "ETH-PDU: Do not support IE ethernet_pdu_session_information yet!");
      // TODO [ETH-PDU] add downlink by UE MAC
    } else {
      cause.cause_value = CAUSE_VALUE_REQUEST_REJECTED;
      Logger::upf_n4().info(
          "Could not create_packet_in_access, cause accept only IPv4 UE IP "
          "address! Rejecting PFCP_XXX_REQUEST");
      return false;
    }
    add(spdr);
  } else {
    cause.cause_value = CAUSE_VALUE_REQUEST_REJECTED;
    Logger::upf_n4().info(
        "Do not actually support other interface type value as ACCESS and CORE "
        "in PFCP_XXX_REQUEST! Rejecting PFCP_XXX_REQUEST");
    return false;
  }

  // TODO [ETH-PDU] set pdn type based on PFCP PDN Type IE
  // If there is ethernet packet filter, then set PDN type to ETHERNET
  if (pdi.ethernet_pdu_session_information.first ||
      pdi.ethernet_packet_filter.first) {
    Logger::upf_n4().info(
        "ETH-PDU: Setting PDN type to ETHERNET based on "
        "ethernet_pdu_session_information or ethernet_packet_filter");
    set(pfcp::pdn_type_value_e::ETHERNET);
  }
  cause.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
  return true;
}

//------------------------------------------------------------------------------
// create_qer — 3GPP TS 29.244 Table 7.5.2.5-1
// QFI is mandatory; GBR without MBR is invalid.

//------------------------------------------------------------------------------
bool pfcp_session::create(
    const pfcp::create_qer& cr_qer, pfcp::cause_t& cause,
    uint16_t& offending_ie) {
  if (not cr_qer.qer_id.first) {
    cause.cause_value = CAUSE_VALUE_CONDITIONAL_IE_MISSING;
    offending_ie      = PFCP_IE_QER_ID;
    // return false;
  }

  /*
  if (not cr_qer.qer_correlation_id.first) {
    cause.cause_value = CAUSE_VALUE_CONDITIONAL_IE_MISSING;
    offending_ie      = PFCP_IE_QER_CORRELATION_ID;
    return false;
  }
  */

  // Gate Status is optional, only log if missing
  if (not cr_qer.gate_status.first) {
    // cause.cause_value = CAUSE_VALUE_CONDITIONAL_IE_MISSING;
    // offending_ie      = PFCP_IE_GATE_STATUS;
    // return false;
    Logger::upf_n4().debug(
        "QER ID %d: Gate Status not provided", cr_qer.qer_id.second.qer_id);
  }

  // MBR and GBR validation
  // According to 3GPP TS 29.244:
  // - For GBR QoS flows: Both MBR and GBR are mandatory
  // - For non-GBR QoS flows: Only MBR may be present, GBR should not be present
  // - For best-effort flows: Neither MBR nor GBR are required

  bool has_mbr = cr_qer.maximum_bitrate.first;
  bool has_gbr = cr_qer.guaranteed_bitrate.first;

  if (has_mbr && has_gbr) {
    // GBR QoS flow (§8.2.8 MBR / §8.2.9 GBR) — both present, validate GBR <=
    // MBR MBR values
    Logger::upf_n4().debug(
        "QER ID %d: GBR QoS flow detected (MBR and GBR present)",
        cr_qer.qer_id.second.qer_id);
    // Optionally validate: GBR UL <= MBR UL and GBR DL <= MBR DL
    if (cr_qer.guaranteed_bitrate.second.ul_gbr >
            cr_qer.maximum_bitrate.second.ul_mbr ||
        cr_qer.guaranteed_bitrate.second.dl_gbr >
            cr_qer.maximum_bitrate.second.dl_mbr) {
      Logger::upf_n4().warn(
          "QER ID %d: GBR exceeds MBR (UL_GBR: %lu > UL_MBR: %lu or DL_GBR: "
          "%lu > DL_MBR: %lu)",
          cr_qer.qer_id.second.qer_id, cr_qer.guaranteed_bitrate.second.ul_gbr,
          cr_qer.maximum_bitrate.second.ul_mbr,
          cr_qer.guaranteed_bitrate.second.dl_gbr,
          cr_qer.maximum_bitrate.second.dl_mbr);
    }
  } else if (has_mbr && !has_gbr) {
    // Non-GBR QoS flow - only MBR present
    Logger::upf_n4().debug(
        "QER ID %d: Non-GBR QoS flow (MBR present, no GBR)",
        cr_qer.qer_id.second.qer_id);
  } else if (!has_mbr && has_gbr) {
    // Invalid: GBR without MBR
    cause.cause_value = CAUSE_VALUE_CONDITIONAL_IE_MISSING;
    offending_ie      = PFCP_IE_MBR;
    Logger::upf_n4().error(
        "QER ID %d: GBR provided without MBR (invalid configuration)",
        cr_qer.qer_id.second.qer_id);
    return false;
  } else {
    // Best-effort flow - neither MBR nor GBR
    Logger::upf_n4().debug(
        "QER ID %d: Best-effort QoS flow (no MBR, no GBR)",
        cr_qer.qer_id.second.qer_id);
  }

  // QFI (§8.2.89) is mandatory according to 3GPP TS 29.244
  if (not cr_qer.qos_flow_identifier.first) {
    cause.cause_value = CAUSE_VALUE_CONDITIONAL_IE_MISSING;
    offending_ie      = PFCP_IE_QFI;
    Logger::upf_n4().error(
        "QER ID %d: QFI is mandatory but missing", cr_qer.qer_id.second.qer_id);
    return false;
  }

  /*
  if (not cr_qer.packet_rate.first) {
    cause.cause_value = CAUSE_VALUE_SERVICE_NOT_SUPPORTED;
    offending_ie      = PFCP_IE_PACKET_RATE;
    return false;
  }
  */

  /*
  if (not cr_qer.dl_flow_level_marking.first) {
    cause.cause_value = CAUSE_VALUE_SERVICE_NOT_SUPPORTED;
    offending_ie      = PFCP_IE_DL_FLOW_LEVEL_MARKING;
    return false;
  }
  */

  /*
  if (not cr_qer.reflective_qos.first) {
    cause.cause_value = CAUSE_VALUE_CONDITIONAL_IE_MISSING;
    offending_ie      = PFCP_IE_RQI;
    return false;
  }
  */

  pfcp_qer* qer                  = new pfcp_qer(cr_qer);
  std::shared_ptr<pfcp_qer> sqer = std::shared_ptr<pfcp_qer>(qer);
  add(sqer);
  cause.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
  return true;
}

// =============================================================================
// Cleanup and display
// =============================================================================

//------------------------------------------------------------------------------
// cleanup — remove all tun/teid mappings from pfcp_switch lookup tables then
// clear all rule vectors.

//------------------------------------------------------------------------------
void pfcp_session::cleanup() {
  for (auto it = pdrs.begin(); it != pdrs.end(); ++it) {
    if (((*it)->pdi.first) && ((*it)->pdi.second.source_interface.first)) {
      if ((*it)->pdi.second.source_interface.second.interface_value ==
          INTERFACE_VALUE_ACCESS) {
        if ((*it)->pdi.second.local_fteid.first) {
          pfcp_switch_inst->remove_pfcp_ul_pdrs_by_up_teid(
              (*it)->pdi.second.local_fteid.second.teid);
        }
      } else if (
          (*it)->pdi.second.source_interface.second.interface_value ==
          INTERFACE_VALUE_CORE) {
        if (((*it)->pdi.second.ue_ip_address.first) &&
            ((*it)->pdi.second.ue_ip_address.second.v4)) {
          pfcp_switch_inst->remove_pfcp_dl_pdrs_by_ue_ip(be32toh(
              (*it)->pdi.second.ue_ip_address.second.ipv4_address.s_addr));
        }
      }
    }
  }
  fars.clear();
  pdrs.clear();
  urrs.clear();
  bars.clear();
  mars.clear();
}

//------------------------------------------------------------------------------
// to_string — render all session PDRs as a formatted ASCII table.

//------------------------------------------------------------------------------
std::string pfcp_session::to_string() const {
  std::ostringstream oss;

  // Table header
  oss << "\n";
  oss << "  "
         "┌────────────────────────────────────────────────────────────────────"
         "──────────────────────────────────────────────────────────────────"
         "─────────────────────────────────┐\n";
  oss << fmt::format(
      "  │{:^167}│\n", fmt::format("PDU SESSION RULES - Session {:#x}", seid));
  oss << "  "
         "├────────┬───────┬───────┬────────────┬───────────┬─────────────────┬"
         "────────────┬────────────┬───────┬────────────────────────────────┬──"
         "──────────────────────────────┤\n";
  oss << "  │  PDR   │  FAR  │  QER  │ Precedence │ Direction │    UE IPv4     "
         " │   Action   │  Dest If   │  QFI  │       Create Outer Hdr         "
         "│       Remove Outer Hdr         │\n";
  oss << "  "
         "├────────┼───────┼───────┼────────────┼───────────┼─────────────────┼"
         "────────────┼────────────┼───────┼────────────────────────────────┼──"
         "──────────────────────────────┤\n";

  // Process each PDR
  for (const auto& pdr : pdrs) {
    std::shared_ptr<pfcp::pfcp_far> far = nullptr;
    std::shared_ptr<pfcp::pfcp_qer> qer = nullptr;

    // Get associated FAR
    if (pdr->far_id.first) {
      get(pdr->far_id.second.far_id, far);
    }

    // Get associated QER
    if (pdr->qer_id.first) {
      get(pdr->qer_id.second.qer_id, qer);
    }

    // PDR ID (left-aligned)
    oss << fmt::format("  │ {:<6} │", pdr->pdr_id.rule_id);

    // FAR ID (left-aligned)
    if (far) {
      oss << fmt::format(" {:<5} │", far->far_id.far_id);
    } else {
      oss << " -     │";
    }

    // QER ID (left-aligned)
    if (qer) {
      oss << fmt::format(" {:<5} │", qer->qer_id.second.qer_id);
    } else {
      oss << " -     │";
    }

    // Precedence (left-aligned)
    if (pdr->precedence.first) {
      oss << fmt::format(" {:<10} │", pdr->precedence.second.precedence);
    } else {
      oss << " -          │";
    }

    // Direction and UE IP
    std::string direction = "?";
    std::string ue_ip     = "";

    if (pdr->pdi.first) {
      // Get UE IP
      if (pdr->pdi.second.ue_ip_address.first &&
          pdr->pdi.second.ue_ip_address.second.v4) {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(
            AF_INET, &pdr->pdi.second.ue_ip_address.second.ipv4_address, ip_str,
            INET_ADDRSTRLEN);
        ue_ip = ip_str;
      }

      // Determine direction
      if (pdr->pdi.second.source_interface.first) {
        switch (pdr->pdi.second.source_interface.second.interface_value) {
          case INTERFACE_VALUE_ACCESS:
            direction = "UL";
            break;
          case INTERFACE_VALUE_CORE:
            direction = "DL";
            break;
          case pfcp::INTERFACE_VALUE_SGI_LAN_N6_LAN:
            direction = "LAN";
            break;
          case pfcp::INTERFACE_VALUE_CP_FUNCTION:
            direction = "CP";
            break;
          case pfcp::INTERFACE_VALUE_LI_FUNCTION:
            direction = "LI";
            break;
          default:
            direction = "?";
            break;
        }
      }
    }

    // Direction (left-aligned)
    oss << fmt::format(" {:<9} │", direction);
    // UE IPv4 (left-aligned)
    oss << fmt::format(" {:<15} │", ue_ip.empty() ? "-" : ue_ip);

    // Action (from FAR apply_action) - left-aligned
    std::string action = "";
    if (far) {
      std::vector<std::string> actions;
      if (far->apply_action.forw) actions.push_back("FORW");
      if (far->apply_action.drop) actions.push_back("DROP");
      if (far->apply_action.buff) actions.push_back("BUFF");
      if (far->apply_action.nocp) actions.push_back("NOCP");
      if (far->apply_action.dupl) actions.push_back("DUPL");

      if (!actions.empty()) {
        for (size_t i = 0; i < actions.size(); ++i) {
          action += actions[i];
          if (i < actions.size() - 1) action += ",";
        }
      }
    }
    oss << fmt::format(" {:<10} │", action.empty() ? "-" : action);

    // Destination Interface (from FAR forwarding parameters) - left-aligned
    std::string dest_if = "";
    if (far && far->forwarding_parameters.first &&
        far->forwarding_parameters.second.destination_interface.first) {
      switch (far->forwarding_parameters.second.destination_interface.second
                  .interface_value) {
        case INTERFACE_VALUE_ACCESS:
          dest_if = "ACCESS";
          break;
        case INTERFACE_VALUE_CORE:
          dest_if = "CORE";
          break;
        case INTERFACE_VALUE_SGI_LAN_N6_LAN:
          dest_if = "SGi-LAN";
          break;
        case INTERFACE_VALUE_CP_FUNCTION:
          dest_if = "CP-FUNC";
          break;
        case INTERFACE_VALUE_LI_FUNCTION:
          dest_if = "LI-FUNC";
          break;
        default:
          dest_if = "?";
          break;
      }
    }
    oss << fmt::format(" {:<10} │", dest_if.empty() ? "-" : dest_if);

    // QFI (QoS Flow Identifier from QER) - left-aligned
    std::string qfi_str = "";
    if (qer && qer->qos_flow_id.first) {
      qfi_str = std::to_string(qer->qos_flow_id.second.qfi);
    }
    if (!qfi_str.empty()) {
      oss << fmt::format(" {:<5} │", qfi_str);
    } else {
      oss << " -     │";
    }

    // Create Outer Header (from FAR) - left-aligned, wider column
    std::string create_hdr = "";
    if (far && far->forwarding_parameters.first &&
        far->forwarding_parameters.second.outer_header_creation.first) {
      auto& ohc =
          far->forwarding_parameters.second.outer_header_creation.second;

      switch (ohc.outer_header_creation_description) {
        case OUTER_HEADER_CREATION_GTPU_UDP_IPV4: {
          char ip_str[INET_ADDRSTRLEN];
          inet_ntop(AF_INET, &ohc.ipv4_address, ip_str, INET_ADDRSTRLEN);
          create_hdr = fmt::format("GTP → {}:{:#x}", ip_str, ohc.teid);
          break;
        }
        case OUTER_HEADER_CREATION_GTPU_UDP_IPV6: {
          char ip_str[INET6_ADDRSTRLEN];
          inet_ntop(AF_INET6, &ohc.ipv6_address, ip_str, INET6_ADDRSTRLEN);
          create_hdr = fmt::format("GTP6 → {}:{:#x}", ip_str, ohc.teid);
          break;
        }
        case OUTER_HEADER_CREATION_UDP_IPV4: {
          char ip_str[INET_ADDRSTRLEN];
          inet_ntop(AF_INET, &ohc.ipv4_address, ip_str, INET_ADDRSTRLEN);
          create_hdr = fmt::format("UDP → {}", ip_str);
          break;
        }
        case OUTER_HEADER_CREATION_UDP_IPV6: {
          create_hdr = "UDP6";
          break;
        }
        default:
          create_hdr = "?";
          break;
      }
    }
    oss << fmt::format(" {:<30} │", create_hdr.empty() ? "-" : create_hdr);

    // Remove Outer Header (from PDR) - left-aligned, wider column
    std::string remove_hdr = "";
    if (pdr->outer_header_removal.first) {
      switch (
          pdr->outer_header_removal.second.outer_header_removal_description) {
        case OUTER_HEADER_REMOVAL_GTPU_UDP_IPV4:
          if (pdr->pdi.second.local_fteid.first) {
            remove_hdr = fmt::format(
                "GTP TEID:{:#x}", pdr->pdi.second.local_fteid.second.teid);
          } else {
            remove_hdr = "GTP/UDP/IPv4";
          }
          break;
        case OUTER_HEADER_REMOVAL_GTPU_UDP_IPV6:
          if (pdr->pdi.second.local_fteid.first) {
            remove_hdr = fmt::format(
                "GTP6 TEID:{:#x}", pdr->pdi.second.local_fteid.second.teid);
          } else {
            remove_hdr = "GTP/UDP/IPv6";
          }
          break;
        case OUTER_HEADER_REMOVAL_UDP_IPV4:
          remove_hdr = "UDP/IPv4";
          break;
        case OUTER_HEADER_REMOVAL_UDP_IPV6:
          remove_hdr = "UDP/IPv6";
          break;
        default:
          remove_hdr = "?";
          break;
      }
    }
    oss << fmt::format(" {:<30} │\n", remove_hdr.empty() ? "-" : remove_hdr);
  }

  // Table footer
  oss << "  "
         "└────────┴───────┴───────┴────────────┴───────────┴─────────────────┴"
         "────────────┴────────────┴───────┴────────────────────────────────┴──"
         "──────────────────────────────┘\n";
  oss << "\n";

  return oss.str();
}
