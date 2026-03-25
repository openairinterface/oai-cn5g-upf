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
 * Changes:     Own lifecycle_ (BPFProgram pattern). No upf_cfg.
 *              Added Load(), GetBpfObject(), GetXdpProgram().
 *              All session lifecycle methods preserved unchanged.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 ss7.5.2.3 Create PDR
 */
// clang-format on

#include "pdr_match_user.h"
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <stdexcept>
#include <wrappers/BPFMap.hpp>
#include "logger.hpp"
#include "upf_network_config.h"
#include "SdfFilterParser.hpp"
#include <sdf_filter.h>

/* Section: Skeleton lifecycle */

//------------------------------------------------------------------------------
PdrMatchProgram::PdrMatchProgram() : BPFProgram() {
  auto open_fn = [this]() -> xdp_pdr_match_kern_c* {
    auto* s = xdp_pdr_match_kern_c__open();
    if (!s) throw std::runtime_error("Failed to open xdp_pdr_match skeleton");
    uint32_t total_sdf =
        upf::GetMaxPduSessions() * upf::GetMaxSdfFiltersPerSession();
    struct bpf_map* m = bpf_object__find_map_by_name(s->obj, "sdf_filters_map");
    if (m) bpf_map__set_max_entries(m, total_sdf);
    if (s->rodata) {
      s->rodata->MAX_PDU_SESSIONS         = upf::GetMaxPduSessions();
      s->rodata->MAX_PDRS_PER_PDU_SESSION = upf::GetMaxPdrsPerSession();
      s->rodata->MAX_SDF_FILTERS_PER_PDU_SESSION =
          upf::GetMaxSdfFiltersPerSession();
    }
    return s;
  };
  lifecycle_ = std::make_shared<PdrMatchProgramLifeCycle>(
      open_fn, xdp_pdr_match_kern_c__load, xdp_pdr_match_kern_c__attach,
      xdp_pdr_match_kern_c__destroy);
  skeleton_ = lifecycle_->open();
  Logger::upf_app().debug("PdrMatchProgram: skeleton opened");
}

//------------------------------------------------------------------------------
void PdrMatchProgram::Load() {
  lifecycle_->load();
  Logger::upf_app().debug("PdrMatchProgram: skeleton loaded");
}

//------------------------------------------------------------------------------
struct bpf_object* PdrMatchProgram::GetBpfObject() const {
  return skeleton_ ? skeleton_->obj : nullptr;
}

//------------------------------------------------------------------------------
struct bpf_program* PdrMatchProgram::GetXdpProgram() const {
  return skeleton_ ? skeleton_->progs.pdr_match : nullptr;
}

/* Section: Map injection */

//------------------------------------------------------------------------------
void PdrMatchProgram::SetMaps(
    std::shared_ptr<BPFMap> session_pdrs_map,
    std::shared_ptr<BPFMap> rules_match_map,
    std::shared_ptr<BPFMap> sdf_filter_map) {
  session_pdrs_map_ = std::move(session_pdrs_map);
  rules_match_map_  = std::move(rules_match_map);
  sdf_filter_map_   = std::move(sdf_filter_map);
  Logger::upf_app().debug("PdrMatchProgram: maps set");
}

/* Section: Static helpers */

//------------------------------------------------------------------------------
pdr_rule_key PdrMatchProgram::MakePdrKey(uint64_t seid, uint32_t pdr_id) {
  pdr_rule_key k;
  k.seid   = seid;
  k.pdr_id = pdr_id;
  k._pad   = 0;
  return k;
}

/* Section: Session lifecycle */

//------------------------------------------------------------------------------
void PdrMatchProgram::PopulateSdfFilterMap(
    uint64_t seid, const std::shared_ptr<pfcp::pfcp_pdr>& pdr) {
  if (!pdr || !sdf_filter_map_) return;
  pfcp::pdi pdi;
  if (!pdr->get(pdi)) return;
  pfcp::sdf_filter_t sdf;
  if (!pdi.get(sdf) || !sdf.fd || sdf.length_of_flow_description == 0) return;
  auto filter_opt = SdfFilterParser::ParseSdfFilter(sdf.flow_description);
  if (!filter_opt) return;
  pdr_rule_key key = MakePdrKey(seid, pdr->pdr_id.rule_id);
  sdf_filter_map_->Update(key, *filter_opt, BPF_ANY);
}

//------------------------------------------------------------------------------
void PdrMatchProgram::PopulateRulesMatchPdrMap(
    uint64_t seid, const std::shared_ptr<pfcp::pfcp_pdr>& pdr,
    uint32_t rules_enabled) {
  if (!pdr || !rules_match_map_) return;
  pdr_rule_association assoc{};
  assoc.pdr_id        = pdr->pdr_id.rule_id;
  assoc.rules_enabled = rules_enabled;
  if (pdr->far_id.first) assoc.far_id = pdr->far_id.second.far_id;
  if (pdr->qer_id.first) assoc.qer_id = pdr->qer_id.second.qer_id;
  if (pdr->urr_id.first) assoc.urr_id = pdr->urr_id.second.urr_id;
  pdr_rule_key key = MakePdrKey(seid, assoc.pdr_id);
  rules_match_map_->Update(key, assoc, BPF_ANY);
}

//------------------------------------------------------------------------------
void PdrMatchProgram::PopulatePdrRulesMaps(
    uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs_ul,
    const std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs_dl,
    uint32_t rules_enabled) {
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
  for (const auto& pdr : pdrs) {
    if (!pdr) continue;
    pdr_rule_key key = MakePdrKey(seid, pdr->pdr_id.rule_id);
    if (rules_match_map_) rules_match_map_->Remove(key);
    if (sdf_filter_map_) sdf_filter_map_->Remove(key);
  }
  if (session_pdrs_map_) session_pdrs_map_->Remove(seid);
}