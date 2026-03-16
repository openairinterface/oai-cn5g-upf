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
 * Changes:     Boy Scout cleanup — changelog and @date normalised.
 *              No functional changes.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 *              §8.2.123  MAR ID   §8.2.125  Steering Mode
 *              §8.2.126  Weight (AFAI)   §8.2.127  Priority (AFAI)
 */
// clang-format on

/**
 * @file mar_xdp_user.cpp
 * @brief Implementation of MAR BPF map manager
 * @author OpenAirInterface, Franck Messaoudi
 * @date 2025 / 2026-03
 */

#include "mar_xdp_user.h"
#include <linux/bpf.h>
#include <cstring>
#include <stdexcept>
#include <wrappers/BPFMap.hpp>
#include "logger.hpp"

//------------------------------------------------------------------------------
MARProgram::MARProgram(std::shared_ptr<BPFMap> mar_rules_map)
    : mar_rules_map_(std::move(mar_rules_map)) {
  if (!mar_rules_map_) {
    throw std::invalid_argument("MARProgram: null BPFMap pointer");
  }
  Logger::upf_app().debug("MARProgram initialised");
}

//------------------------------------------------------------------------------
// static helpers
//------------------------------------------------------------------------------

mar_map_key MARProgram::MakeKey(uint64_t seid, uint32_t mar_id) {
  mar_map_key k;
  k.seid   = seid;
  k.mar_id = mar_id;
  k._pad   = 0;
  return k;
}

//------------------------------------------------------------------------------
// void MARProgram::ConvertMar(
//     const pfcp::pfcp_mar& ie, struct pfcp_mar& bpf_mar) {
//   std::memset(&bpf_mar, 0, sizeof(bpf_mar));

//   bpf_mar.mar_id = ie.mar_id.second.mar_id;

//   // Steering Mode (TS 29.244 Section 8.2.124)
//   if (ie.steering_mode.first) {
//     bpf_mar.steer_mode =
//         static_cast<uint8_t>(ie.steering_mode.second.steering_mode);
//   }

//   // Access Forwarding Action Information — 3GPP access (N3)
//   // (TS 29.244 Section 8.2.75, contains FAR_ID for 3GPP path)
//   if (ie.access_forwarding_action_information_3gpp.first) {
//     const auto& afai = ie.access_forwarding_action_information_3gpp.second;
//     if (afai.far_id.first) {
//       bpf_mar.n3_far_id = afai.far_id.second.far_id;
//     }
//     // active_access / standby_access: relevant for Active-Standby mode
//     bpf_mar.active_access  = ACCESS_3GPP;
//     bpf_mar.standby_access = ACCESS_NON_3GPP;
//   }

//   // Access Forwarding Action Information — non-3GPP access (N9/WLAN)
//   if (ie.access_forwarding_action_information_non3gpp.first) {
//     const auto& afai =
//     ie.access_forwarding_action_information_non3gpp.second; if
//     (afai.far_id.first) {
//       bpf_mar.n9_far_id = afai.far_id.second.far_id;
//     }
//   }
// }

//------------------------------------------------------------------------------
// Public interface
//------------------------------------------------------------------------------

void MARProgram::PopulateMarRulesMap(
    uint64_t seid, const std::shared_ptr<pfcp::pfcp_mar>& ie, uint64_t flags) {
  if (!ie) return;

  struct pfcp_mar bpf_mar;
  ConvertMar(*ie, bpf_mar);

  mar_map_key key = MakeKey(seid, bpf_mar.mar_id);
  int ret         = mar_rules_map_->Update(key, bpf_mar, flags);
  if (ret != 0) {
    Logger::upf_app().error(
        "MAR rules map update failed: SEID=%" PRIu64 " MAR_ID=%u ret=%d", seid,
        bpf_mar.mar_id, ret);
  } else {
    Logger::upf_app().debug(
        "MAR rules map: SEID=%" PRIu64 " MAR_ID=%u mode=%u ", seid,
        bpf_mar.mar_id, bpf_mar.steering_mode.steer_mode_value);
  }
}

//------------------------------------------------------------------------------
void MARProgram::Setup(
    uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_mar>>& mars) {
  Logger::upf_app().debug(
      "MARProgram::Setup SEID=%" PRIu64 " count=%zu", seid, mars.size());
  for (const auto& mar : mars) {
    if (!mar) continue;
    PopulateMarRulesMap(seid, mar, BPF_ANY);
  }
}

//------------------------------------------------------------------------------
void MARProgram::Update(
    uint64_t seid, const std::shared_ptr<pfcp::pfcp_mar>& mar) {
  if (!mar) return;
  Logger::upf_app().debug(
      "MARProgram::Update SEID=%" PRIu64 " MAR_ID=%u", seid,
      mar->mar_id.second.mar_id);
  PopulateMarRulesMap(seid, mar, BPF_EXIST);
}

//------------------------------------------------------------------------------
void MARProgram::Remove(uint64_t seid, uint32_t mar_id) {
  Logger::upf_app().debug(
      "MARProgram::Remove SEID=%" PRIu64 " MAR_ID=%u", seid, mar_id);
  mar_map_key key = MakeKey(seid, mar_id);
  mar_rules_map_->Remove(key);
}

//------------------------------------------------------------------------------
void MARProgram::TearDown(
    uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_mar>>& mars) {
  Logger::upf_app().debug(
      "MARProgram::TearDown SEID=%" PRIu64 " count=%zu", seid, mars.size());
  for (const auto& mar : mars) {
    if (!mar) continue;
    Remove(seid, mar->mar_id.second.mar_id);
  }
}
