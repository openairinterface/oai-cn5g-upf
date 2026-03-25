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

#include "session_lookup_ip_user.h"
#include <bpf/libbpf.h>
#include <stdexcept>
#include <wrappers/BPFMaps.h>
#include "logger.hpp"
#include "upf_network_config.h"

//------------------------------------------------------------------------------
SessionLookupIPProgram::SessionLookupIPProgram() : BPFProgram() {
  auto open_fn = [this]() -> xdp_session_lookup_ip_kern_c* {
    auto* s = xdp_session_lookup_ip_kern_c__open();
    if (!s)
      throw std::runtime_error("Failed to open xdp_session_lookup_ip skeleton");
    auto set_size = [&](const char* name, uint32_t sz) {
      struct bpf_map* m = bpf_object__find_map_by_name(s->obj, name);
      if (m) bpf_map__set_max_entries(m, sz);
    };
    uint32_t max_sessions    = upf::GetMaxPduSessions();
    uint32_t total_pdr_rules = max_sessions * upf::GetMaxPdrsPerSession();
    set_size("session_by_ue_ip_map", max_sessions);
    set_size("pdrs_per_session_map", max_sessions);
    set_size("session_qos_enabled_map", max_sessions);
    set_size("m_framed_route_mapping", max_sessions);
    set_size("rules_match_pdr_map", total_pdr_rules);
    if (s->rodata) {
      s->rodata->MAX_PDU_SESSIONS         = upf::GetMaxPduSessions();
      s->rodata->MAX_PDRS_PER_PDU_SESSION = upf::GetMaxPdrsPerSession();
      s->rodata->MAX_SDF_FILTERS_PER_PDU_SESSION =
          upf::GetMaxSdfFiltersPerSession();
      s->rodata->MAX_UPF_INTERFACES = upf::GetMaxUpfInterfaces();
      s->rodata->MAX_UPF_REDIRECT_INTERFACES =
          upf::GetMaxUpfRedirectInterfaces();
      s->rodata->MAX_ARP_ENTRIES  = upf::GetMaxArpEntries();
      s->rodata->MAX_QOS_ENABLING = upf::GetMaxPduSessions();
    }
    return s;
  };
  lifecycle_ = std::make_shared<SessionLookupIPLifeCycle>(
      open_fn, xdp_session_lookup_ip_kern_c__load,
      xdp_session_lookup_ip_kern_c__attach,
      xdp_session_lookup_ip_kern_c__destroy);
  skeleton_ = lifecycle_->open();
  Logger::upf_app().debug("SessionLookupIPProgram: skeleton opened");
}

//------------------------------------------------------------------------------
SessionLookupIPProgram::~SessionLookupIPProgram() {}

//------------------------------------------------------------------------------
void SessionLookupIPProgram::Load() {
  lifecycle_->load();
  InitializeMaps();
  Logger::upf_app().debug("SessionLookupIPProgram: loaded");
}

//------------------------------------------------------------------------------
struct bpf_object* SessionLookupIPProgram::GetBpfObject() const {
  return skeleton_ ? skeleton_->obj : nullptr;
}

//------------------------------------------------------------------------------
struct bpf_program* SessionLookupIPProgram::GetXdpProgram() const {
  return skeleton_ ? skeleton_->progs.session_lookup_ip : nullptr;
}

//------------------------------------------------------------------------------
void SessionLookupIPProgram::InitializeMaps() {
  maps_ = std::make_shared<BPFMaps>(skeleton_->skeleton);
}

/* Section: Map getters */

std::shared_ptr<BPFMap> SessionLookupIPProgram::GetSessionByUeIpMap() const {
  if (!maps_) return nullptr;
  return std::make_shared<BPFMap>(maps_->GetMap("session_by_ue_ip_map"));
}
std::shared_ptr<BPFMap> SessionLookupIPProgram::GetSessionPdrsMap() const {
  if (!maps_) return nullptr;
  return std::make_shared<BPFMap>(maps_->GetMap("pdrs_per_session_map"));
}
std::shared_ptr<BPFMap> SessionLookupIPProgram::GetRulesMatchMap() const {
  if (!maps_) return nullptr;
  return std::make_shared<BPFMap>(maps_->GetMap("rules_match_pdr_map"));
}
std::shared_ptr<BPFMap> SessionLookupIPProgram::GetSessionQosEnabledMap()
    const {
  if (!maps_) return nullptr;
  return std::make_shared<BPFMap>(maps_->GetMap("session_qos_enabled_map"));
}
std::shared_ptr<BPFMap> SessionLookupIPProgram::GetFramedRouteMappingMap()
    const {
  if (!maps_) return nullptr;
  return std::make_shared<BPFMap>(maps_->GetMap("m_framed_route_mapping"));
}
std::shared_ptr<BPFMap> SessionLookupIPProgram::GetFramedRoutingFlagMap()
    const {
  if (!maps_) return nullptr;
  return std::make_shared<BPFMap>(maps_->GetMap("framed_routing_flag"));
}
std::shared_ptr<BPFMap> SessionLookupIPProgram::GetFeatureDispatchMap() const {
  if (!maps_) return nullptr;
  return std::make_shared<BPFMap>(maps_->GetMap("feature_dispatch_map"));
}