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
 * distributed under the LICENSE is distributed on an "AS IS" BASIS,
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
 * Changes:     Rewrote constructor -- own lifecycle_ (BPFProgram pattern).
 *              Added Load(), GetBpfObject(), GetXdpProgram().
 *              SetMaps() receives refs from UPF_XDPProgram::InitializeMaps().
 *              All session lifecycle methods preserved unchanged. No upf_cfg.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 ss8.2.123 MAR ID
 */
// clang-format on

#include "mar_apply_user.h"
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <stdexcept>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "logger.hpp"
#include "upf_network_config.h"

/* Section: Skeleton lifecycle */

//------------------------------------------------------------------------------
MARProgram::MARProgram() : BPFProgram() {
  auto open_fn = [this]() -> xdp_mar_apply_kern_c* {
    auto* s = xdp_mar_apply_kern_c__open();
    if (!s) throw std::runtime_error("Failed to open xdp_mar_apply skeleton");
    auto set_size = [&](const char* name, uint32_t sz) {
      struct bpf_map* m = bpf_object__find_map_by_name(s->obj, name);
      if (m) bpf_map__set_max_entries(m, sz);
    };
    set_size("mar_config_map", upf::GetMaxPduSessions());
    set_size("mar_access_state_map", upf::GetMaxPduSessions());
    if (s->rodata) s->rodata->MAX_PDU_SESSIONS = upf::GetMaxPduSessions();
    return s;
  };
  lifecycle_ = std::make_shared<MarProgramLifeCycle>(
      open_fn, xdp_mar_apply_kern_c__load, xdp_mar_apply_kern_c__attach,
      xdp_mar_apply_kern_c__destroy);
  skeleton_ = lifecycle_->open();
  Logger::upf_app().debug("MARProgram: skeleton opened");
}

//------------------------------------------------------------------------------
void MARProgram::Load() {
  lifecycle_->load();
  auto maps       = std::make_shared<BPFMaps>(skeleton_->skeleton);
  mar_config_map_ = std::make_shared<BPFMap>(maps->GetMap("mar_config_map"));
  mar_access_state_map_ =
      std::make_shared<BPFMap>(maps->GetMap("mar_access_state_map"));
  Logger::upf_app().debug("MARProgram: skeleton loaded");
}

//------------------------------------------------------------------------------
struct bpf_object* MARProgram::GetBpfObject() const {
  return skeleton_ ? skeleton_->obj : nullptr;
}

//------------------------------------------------------------------------------
struct bpf_program* MARProgram::GetXdpProgram() const {
  return skeleton_ ? skeleton_->progs.mar_apply : nullptr;
}

/* Section: Map injection */

//------------------------------------------------------------------------------
void MARProgram::SetMaps(
    std::shared_ptr<BPFMap> mar_config_map,
    std::shared_ptr<BPFMap> mar_access_state_map) {
  if (!mar_config_map)
    throw std::invalid_argument("MARProgram::SetMaps: null mar_config_map");
  mar_config_map_       = std::move(mar_config_map);
  mar_access_state_map_ = std::move(mar_access_state_map);
  Logger::upf_app().debug("MARProgram: maps set");
}

/* Section: Static helpers */

//------------------------------------------------------------------------------
mar_map_key MARProgram::MakeKey(uint64_t seid, uint32_t mar_id) {
  mar_map_key k;
  k.seid   = seid;
  k.mar_id = mar_id;
  k._pad   = 0;
  return k;
}

/* Section: Session lifecycle */

//------------------------------------------------------------------------------
void MARProgram::PopulateMarRulesMap(
    uint64_t seid, const std::shared_ptr<pfcp::pfcp_mar>& ie, uint64_t flags) {
  if (!ie || !mar_config_map_) return;
  struct pfcp_mar bpf_mar;
  ConvertMar(*ie, bpf_mar);
  mar_map_key key = MakeKey(seid, bpf_mar.mar_id);
  int ret         = mar_config_map_->Update(key, bpf_mar, flags);
  if (ret != 0)
    Logger::upf_app().error(
        "MARProgram: config map update failed SEID=%" PRIu64
        " MAR_ID=%u ret=%d",
        seid, bpf_mar.mar_id, ret);
}

//------------------------------------------------------------------------------
void MARProgram::Setup(
    uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_mar>>& mars) {
  for (const auto& mar : mars) {
    if (!mar) continue;
    PopulateMarRulesMap(seid, mar, BPF_ANY);
  }
}

//------------------------------------------------------------------------------
void MARProgram::Update(
    uint64_t seid, const std::shared_ptr<pfcp::pfcp_mar>& mar) {
  if (!mar) return;
  PopulateMarRulesMap(seid, mar, BPF_EXIST);
}

//------------------------------------------------------------------------------
void MARProgram::Remove(uint64_t seid, uint32_t mar_id) {
  mar_map_key key = MakeKey(seid, mar_id);
  if (mar_config_map_) mar_config_map_->Remove(key);
  if (mar_access_state_map_) mar_access_state_map_->Remove(key);
}

//------------------------------------------------------------------------------
void MARProgram::TearDown(
    uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_mar>>& mars) {
  for (const auto& mar : mars) {
    if (!mar) continue;
    Remove(seid, mar->mar_id.second.mar_id);
  }
}

//------------------------------------------------------------------------------
void MARProgram::ConvertMar(
    const pfcp::pfcp_mar& mar, struct pfcp_mar& bpf_mar) {
  bpf_mar = {};

  bpf_mar.mar_id = mar.mar_id.second.mar_id;

  if (mar.steering_mode.first)
    bpf_mar.steering_mode.steer_mode_value =
        mar.steering_mode.second.steering_mode_value;

  if (mar.access_forwarding_action_info_1.first)
    bpf_mar.access_forwarding_action_info_1.far_id.far_id =
        mar.access_forwarding_action_info_1.second.far_id.far_id;

  if (mar.access_forwarding_action_info_2.first)
    bpf_mar.access_forwarding_action_info_2.far_id.far_id =
        mar.access_forwarding_action_info_2.second.far_id.far_id;
}
