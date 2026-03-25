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
 * Changes:     New file. Own lifecycle_ (BPFProgram pattern). No upf_cfg.
 */
// clang-format on

#include "session_lookup_eth_user.h"
#include <bpf/libbpf.h>
#include <stdexcept>
#include "logger.hpp"
#include "upf_network_config.h"
#include <wrappers/BPFMaps.h>

//------------------------------------------------------------------------------
SessionLookupETHProgram::SessionLookupETHProgram() : BPFProgram() {
  auto open_fn = [this]() -> xdp_session_lookup_eth_kern_c* {
    auto* s = xdp_session_lookup_eth_kern_c__open();
    if (!s)
      throw std::runtime_error(
          "Failed to open xdp_session_lookup_eth skeleton");
    auto set_size = [&](const char* name, uint32_t sz) {
      struct bpf_map* m = bpf_object__find_map_by_name(s->obj, name);
      if (m) bpf_map__set_max_entries(m, sz);
    };
    uint32_t max_sessions    = upf::GetMaxPduSessions();
    uint32_t total_pdr_rules = max_sessions * upf::GetMaxPdrsPerSession();
    set_size("session_by_mac_map", max_sessions);
    set_size("eth_session_mapping_map", max_sessions);
    set_size("eth_session_pdrs_map", max_sessions);
    set_size("eth_rules_match_pdr_map", total_pdr_rules);
    if (s->rodata) s->rodata->MAX_UPF_INTERFACES = upf::GetMaxUpfInterfaces();
    return s;
  };
  lifecycle_ = std::make_shared<SessionLookupETHLifeCycle>(
      open_fn, xdp_session_lookup_eth_kern_c__load,
      xdp_session_lookup_eth_kern_c__attach,
      xdp_session_lookup_eth_kern_c__destroy);
  skeleton_ = lifecycle_->open();
  Logger::upf_app().debug("SessionLookupETHProgram: skeleton opened");
}

//------------------------------------------------------------------------------
SessionLookupETHProgram::~SessionLookupETHProgram() {}

//------------------------------------------------------------------------------
void SessionLookupETHProgram::Load() {
  lifecycle_->load();
  maps_ = std::make_shared<BPFMaps>(skeleton_->skeleton);
  Logger::upf_app().debug("SessionLookupETHProgram: loaded");
}

//------------------------------------------------------------------------------
struct bpf_object* SessionLookupETHProgram::GetBpfObject() const {
  return skeleton_ ? skeleton_->obj : nullptr;
}

//------------------------------------------------------------------------------
struct bpf_program* SessionLookupETHProgram::GetXdpProgram() const {
  return skeleton_ ? skeleton_->progs.session_lookup_eth : nullptr;
}

/* Section: Map getters */

std::shared_ptr<BPFMap> SessionLookupETHProgram::GetSessionByMacMap() const {
  if (!maps_) return nullptr;
  return std::make_shared<BPFMap>(maps_->GetMap("session_by_mac_map"));
}
std::shared_ptr<BPFMap> SessionLookupETHProgram::GetMacPduSessionMap() const {
  if (!maps_) return nullptr;
  return std::make_shared<BPFMap>(maps_->GetMap("mac_pdu_session_map"));
}
std::shared_ptr<BPFMap> SessionLookupETHProgram::GetEthSessionMappingMap()
    const {
  if (!maps_) return nullptr;
  return std::make_shared<BPFMap>(maps_->GetMap("eth_session_mapping_map"));
}
std::shared_ptr<BPFMap> SessionLookupETHProgram::GetEthSessionPdrsMap() const {
  if (!maps_) return nullptr;
  return std::make_shared<BPFMap>(maps_->GetMap("eth_session_pdrs_map"));
}
std::shared_ptr<BPFMap> SessionLookupETHProgram::GetEthRulesMatchPdrMap()
    const {
  if (!maps_) return nullptr;
  return std::make_shared<BPFMap>(maps_->GetMap("eth_rules_match_pdr_map"));
}
std::shared_ptr<BPFMap> SessionLookupETHProgram::GetEthEgressIfindexMap()
    const {
  if (!maps_) return nullptr;
  return std::make_shared<BPFMap>(maps_->GetMap("eth_egress_ifindex_map"));
}