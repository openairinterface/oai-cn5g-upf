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
 *              §7.5.2.3  Create PDR   §8.2.11  Precedence   §8.2.36  PDR ID
 */
// clang-format on

/**
 * @file pdr_match_user.cpp
 * @brief Implementation of PDR matching BPF map manager
 * @author OpenAirInterface, Franck Messaoudi
 * @date 2025 / 2026-03
 */

#include "pdr_match_user.h"
#include <linux/bpf.h>
#include <cstring>
#include <stdexcept>
#include <wrappers/BPFMap.hpp>
#include "logger.hpp"
#include "SdfFilterParser.hpp"  // For parsing SDF filter strings
#include <sdf_filter.h>         // struct sdf_filter (kernel BPF type)

//------------------------------------------------------------------------------
PdrMatchProgram::PdrMatchProgram(
    std::shared_ptr<BPFMap> session_pdrs_map,
    std::shared_ptr<BPFMap> rules_match_map,
    std::shared_ptr<BPFMap> sdf_filter_map)
    : session_pdrs_map_(std::move(session_pdrs_map)),
      rules_match_map_(std::move(rules_match_map)),
      sdf_filter_map_(std::move(sdf_filter_map)) {
  if (!session_pdrs_map_ || !rules_match_map_ || !sdf_filter_map_) {
    throw std::invalid_argument("PdrMatchProgram: null BPFMap pointer");
  }
  Logger::upf_app().debug("PdrMatchProgram initialised");
}

//------------------------------------------------------------------------------
pdr_rule_key PdrMatchProgram::MakePdrKey(uint64_t seid, uint32_t pdr_id) {
  pdr_rule_key k;
  k.seid   = seid;
  k.pdr_id = pdr_id;
  k._pad   = 0;
  return k;
}

//------------------------------------------------------------------------------
void PdrMatchProgram::PopulateSdfFilterMap(
    uint64_t seid, const std::shared_ptr<pfcp::pfcp_pdr>& pdr) {
  if (!pdr) return;

  pfcp::pdi pdi;
  if (!pdr->get(pdi)) return;

  pfcp::sdf_filter_t sdf;
  if (!pdi.get(sdf) || !sdf.fd || sdf.length_of_flow_description == 0) return;

  // Parse the SDF filter string into a BPF-compatible struct
  // (e.g. "permit out ip from 1.2.3.4/24 to any 80")
  auto filter_opt = SdfFilterParser::ParseSdfFilter(sdf.flow_description);
  if (!filter_opt) {
    Logger::upf_app().warn(
        "SDF filter parse failed for PDR %u SEID=%" PRIu64 ": '%s'",
        pdr->pdr_id.rule_id, seid, sdf.flow_description.c_str());
    return;
  }

  pdr_rule_key key = MakePdrKey(seid, pdr->pdr_id.rule_id);
  int ret          = sdf_filter_map_->Update(key, *filter_opt, BPF_ANY);
  if (ret != 0) {
    Logger::upf_app().error(
        "SDF filter map update failed: SEID=%" PRIu64 " PDR=%u ret=%d", seid,
        pdr->pdr_id.rule_id, ret);
  } else {
    Logger::upf_app().debug(
        "SDF filter map: SEID=%" PRIu64 " PDR=%u '%s'", seid,
        pdr->pdr_id.rule_id, sdf.flow_description.c_str());
  }
}

//------------------------------------------------------------------------------
void PdrMatchProgram::PopulateRulesMatchPdrMap(
    uint64_t seid, const std::shared_ptr<pfcp::pfcp_pdr>& pdr,
    uint32_t rules_enabled) {
  if (!pdr) return;

  pdr_rule_association assoc{};
  assoc.pdr_id        = pdr->pdr_id.rule_id;
  assoc.rules_enabled = rules_enabled;

  // FAR ID (mandatory — every PDR references exactly one FAR)
  if (pdr->far_id.first) {
    assoc.far_id = pdr->far_id.second.far_id;
  }

  // QER ID (optional)
  if (pdr->qer_id.first) {
    assoc.qer_id = pdr->qer_id.second.qer_id;
  }

  // URR ID (optional)
  if (pdr->urr_id.first) {
    assoc.urr_id = pdr->urr_id.second.urr_id;
  }

  // BAR is linked via FAR → BAR_ID chain; carried here for fast path access
  // (populated by SessionProgramManager from the session's FAR list)

  // MAR ID: SessionProgramManager sets assoc.mar_id after looking up
  // the PDR's associated MAR from the session.

  pdr_rule_key key = MakePdrKey(seid, assoc.pdr_id);
  int ret          = rules_match_map_->Update(key, assoc, BPF_ANY);
  if (ret != 0) {
    Logger::upf_app().error(
        "rules_match_pdr_map update failed: SEID=%" PRIu64 " PDR=%u ret=%d",
        seid, assoc.pdr_id, ret);
  } else {
    Logger::upf_app().debug(
        "rules_match_pdr_map: SEID=%" PRIu64
        " PDR=%u FAR=%u QER=%u URR=%u flags=0x%02x",
        seid, assoc.pdr_id, assoc.far_id, assoc.qer_id, assoc.urr_id,
        assoc.rules_enabled);
  }
}

//------------------------------------------------------------------------------
void PdrMatchProgram::PopulatePdrRulesMaps(
    uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs_ul,
    const std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs_dl,
    uint32_t rules_enabled) {
  Logger::upf_app().debug(
      "PdrMatchProgram::PopulatePdrRulesMaps SEID=%" PRIu64
      " UL=%zu DL=%zu flags=0x%02x",
      seid, pdrs_ul.size(), pdrs_dl.size(), rules_enabled);

  // Write session PDR array into pdrs_per_session_map.
  // The kernel map value type is a struct holding the PDR count + array;
  // SessionProgramManager provides the pre-built value via its own
  // ConvertPdrSession() helper which knows the exact kernel struct layout.
  // PdrMatchProgram only populates the auxiliary per-PDR maps here.

  // Populate rules_match_pdr_map and sdf_filters_map for each PDR
  for (const auto& pdr : pdrs_ul) {
    PopulateRulesMatchPdrMap(seid, pdr, rules_enabled);
    PopulateSdfFilterMap(seid, pdr);
  }
  for (const auto& pdr : pdrs_dl) {
    PopulateRulesMatchPdrMap(seid, pdr, rules_enabled);
    PopulateSdfFilterMap(seid, pdr);
  }
}

//------------------------------------------------------------------------------
void PdrMatchProgram::RemovePdrRulesMaps(
    uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs) {
  Logger::upf_app().debug(
      "PdrMatchProgram::RemovePdrRulesMaps SEID=%" PRIu64 " count=%zu", seid,
      pdrs.size());

  for (const auto& pdr : pdrs) {
    if (!pdr) continue;
    uint32_t pdr_id  = pdr->pdr_id.rule_id;
    pdr_rule_key key = MakePdrKey(seid, pdr_id);
    rules_match_map_->Remove(key);
    sdf_filter_map_->Remove(key);
  }

  // Remove the session entry from pdrs_per_session_map
  session_pdrs_map_->Remove(seid);
}
