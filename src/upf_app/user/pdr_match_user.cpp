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
 * Changes:     Rewritten to follow n3_entry_user.cpp / session_lookup_ip_user.cpp
 *              pattern exactly.
 *              Constructor no longer opens the skeleton -- open is lazy.
 *              ConfigureMaps uses ConfigureMapMaxEntries(skel->maps.xxx).
 *              Setup() = open (idempotent) + InitializeMaps + load.
 *              No attach() / link() -- stage program, reached via tail call.
 *              All session lifecycle methods preserved unchanged.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 §7.5.2.3 Create PDR
 */
// clang-format on

#include "pdr_match_user.h"
#include <bpf/libbpf.h>
#include <stdexcept>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "logger.hpp"
#include "upf_xdp_limits.h"
#include "utils/bpf_utils.hpp"
#include "SdfFilterParser.hpp"
#include <sdf_filter.h>

using namespace oai::utils::bpf;

//------------------------------------------------------------------------------
void PdrMatchProgram::ConfigureMaps(struct xdp_pdr_match_kern_c* skel) {
  if (!skel) {
    Logger::upf_app().error("Null skeleton in PdrMatchProgram::ConfigureMaps");
    return;
  }

  bool ok = true;

  /* sdf_maps.h -- owned by PdrMatchProgram, runtime-sized */
  ok &= ConfigureMapMaxEntries(
      skel->maps.sdf_filters_map, "sdf_filters_map",
      upf::GetMaxPduSessions() * upf::GetMaxSdfFiltersPerSession());

  /*
   * pipeline_maps.h maps (pdrs_per_session_map, rules_match_pdr_map) are
   * shared from the primary entry program via bpf_map__reuse_fd before
   * Setup() is called. They must NOT be sized here.
   */

  if (!ok) {
    Logger::upf_app().error(
        "One or more map configurations failed for PdrMatchProgram.");
    throw std::runtime_error("PdrMatchProgram map configuration failed");
  }

  /* rodata: 7 fields.
   * xdp_pdr_match_kern.c includes pipeline_maps.h to declare the shared maps
   * (pdrs_per_session_map, rules_match_pdr_map). pipeline_maps.h declares all
   * 7 rodata fields and is a superset of sdf_maps.h rodata. */
  if (skel->rodata) {
    skel->rodata->MAX_UPF_INTERFACES = upf::GetMaxUpfInterfaces();
    skel->rodata->MAX_UPF_REDIRECT_INTERFACES =
        upf::GetMaxUpfRedirectInterfaces();
    skel->rodata->MAX_PDU_SESSIONS         = upf::GetMaxPduSessions();
    skel->rodata->MAX_PDRS_PER_PDU_SESSION = upf::GetMaxPdrsPerSession();
    skel->rodata->MAX_SDF_FILTERS_PER_PDU_SESSION =
        upf::GetMaxSdfFiltersPerSession();
    skel->rodata->MAX_ARP_ENTRIES  = upf::GetMaxArpEntries();
    skel->rodata->MAX_QOS_ENABLING = upf::GetMaxPduSessions();
  }
}

//------------------------------------------------------------------------------
PdrMatchProgram::PdrMatchProgram() : BPFProgram() {
  Logger::upf_app().debug("Initializing PDR Match XDP Program ...");

  auto open_fn = [this]() -> xdp_pdr_match_kern_c* {
    struct xdp_pdr_match_kern_c* s = xdp_pdr_match_kern_c__open();
    if (!s) {
      Logger::upf_app().error("Failed to open xdp_pdr_match skeleton");
      return nullptr;
    }
    // Configure maps and rodata before skeleton is loaded
    this->ConfigureMaps(s);
    // Store skeleton pointer -- available from this point onwards
    skeleton_ = s;
    return s;
  };

  lifecycle_ = std::make_shared<PdrMatchProgramLifeCycle>(
      open_fn,
      /* load    */ xdp_pdr_match_kern_c__load,
      /* attach  */ xdp_pdr_match_kern_c__attach,
      /* destroy */ xdp_pdr_match_kern_c__destroy, "PdrMatchProgram");
}

//------------------------------------------------------------------------------
void PdrMatchProgram::Setup() {
  /*
   * lifecycle_->open() is idempotent: if UPF_XDPProgram already called it
   * (to get the bpf_object for ShareMaps before loading), this returns the
   * cached skeleton with no side effects.
   */
  skeleton_ = lifecycle_->open();
  InitializeMaps();
  lifecycle_->load();
}

//------------------------------------------------------------------------------
void PdrMatchProgram::TearDown() {
  lifecycle_->tearDown();
}

//------------------------------------------------------------------------------
void PdrMatchProgram::InitializeMaps() {
  maps_    = std::make_shared<BPFMaps>(lifecycle_->getBPFSkeleton()->skeleton);
  auto get = [&](const char* name) {
    return std::make_shared<BPFMap>(maps_->GetMap(name));
  };
  /* sdf_maps.h -- owned */
  sdf_filter_map_ = get("sdf_filters_map");
  /* pipeline_maps.h -- shared from primary via reuse_fd */
  session_pdrs_map_ = get("pdrs_per_session_map");
  rules_match_map_  = get("rules_match_pdr_map");
}

//------------------------------------------------------------------------------
struct bpf_object* PdrMatchProgram::GetBpfObject() const {
  return skeleton_ ? skeleton_->obj : nullptr;
}

//------------------------------------------------------------------------------
struct bpf_object_skeleton* PdrMatchProgram::GetSkeleton() const {
  return skeleton_ ? skeleton_->skeleton : nullptr;
}

//------------------------------------------------------------------------------
struct bpf_program* PdrMatchProgram::GetXdpProgram() const {
  return skeleton_ ? skeleton_->progs.pdr_match : nullptr;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMaps> PdrMatchProgram::GetMaps() const {
  return maps_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> PdrMatchProgram::GetSdfFilterMap() const {
  return sdf_filter_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> PdrMatchProgram::GetSessionPdrsMap() const {
  return session_pdrs_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> PdrMatchProgram::GetRulesMatchMap() const {
  return rules_match_map_;
}

//------------------------------------------------------------------------------
/*
 * TODO(fmessaoudi): See TODO in n3_entry_user.cpp -- GetMapCount() ownership.
 */
size_t PdrMatchProgram::GetMapCount() const {
  return maps_ ? maps_->GetMapCount() : 0;
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

  auto filter_opt = SdfFilterParser::ParseSdfFilter(sdf.flow_description);
  if (!filter_opt) return;

  if (!sdf_filter_map_) return;
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
