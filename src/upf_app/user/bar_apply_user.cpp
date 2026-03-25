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
 * Changes:     Rewrote constructor -- own lifecycle_ (BPFProgram pattern).
 *              Added Load(), GetBpfObject(), GetXdpProgram().
 *              SetMaps() receives refs from UPF_XDPProgram::InitializeMaps().
 *              All session lifecycle methods preserved unchanged. No upf_cfg.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 ss8.2.57 BAR ID
 */
// clang-format on

#include "bar_apply_user.h"
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <cerrno>
#include <stdexcept>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "logger.hpp"
#include "upf_network_config.h"

/* Section: Skeleton lifecycle */

//------------------------------------------------------------------------------
BARProgram::BARProgram() : BPFProgram() {
  auto open_fn = [this]() -> xdp_bar_apply_kern_c* {
    auto* s = xdp_bar_apply_kern_c__open();
    if (!s) throw std::runtime_error("Failed to open xdp_bar_apply skeleton");
    auto set_size = [&](const char* name, uint32_t sz) {
      struct bpf_map* m = bpf_object__find_map_by_name(s->obj, name);
      if (m) bpf_map__set_max_entries(m, sz);
    };
    set_size("bar_config_map", upf::GetMaxPduSessions());
    set_size("bar_state_map", upf::GetMaxPduSessions());
    return s;
  };
  lifecycle_ = std::make_shared<BarProgramLifeCycle>(
      open_fn, xdp_bar_apply_kern_c__load, xdp_bar_apply_kern_c__attach,
      xdp_bar_apply_kern_c__destroy);
  skeleton_ = lifecycle_->open();
  Logger::upf_app().debug("BARProgram: skeleton opened");
}

//------------------------------------------------------------------------------
void BARProgram::Load() {
  lifecycle_->load();
  auto maps       = std::make_shared<BPFMaps>(skeleton_->skeleton);
  bar_config_map_ = std::make_shared<BPFMap>(maps->GetMap("bar_config_map"));
  bar_state_map_  = std::make_shared<BPFMap>(maps->GetMap("bar_state_map"));
  Logger::upf_app().debug("BARProgram: skeleton loaded");
}

//------------------------------------------------------------------------------
struct bpf_object* BARProgram::GetBpfObject() const {
  return skeleton_ ? skeleton_->obj : nullptr;
}

//------------------------------------------------------------------------------
struct bpf_program* BARProgram::GetXdpProgram() const {
  return skeleton_ ? skeleton_->progs.bar_apply : nullptr;
}

/* Section: Map injection */

//------------------------------------------------------------------------------
void BARProgram::SetMaps(
    std::shared_ptr<BPFMap> bar_config_map,
    std::shared_ptr<BPFMap> bar_state_map) {
  if (!bar_config_map || !bar_state_map)
    throw std::invalid_argument("BARProgram::SetMaps: null BPFMap pointer");
  bar_config_map_ = std::move(bar_config_map);
  bar_state_map_  = std::move(bar_state_map);
  Logger::upf_app().debug("BARProgram: maps set");
}

/* Section: Static helpers */

//------------------------------------------------------------------------------
bar_map_key BARProgram::MakeKey(uint64_t seid, uint32_t bar_id) {
  bar_map_key k;
  k.seid   = seid;
  k.bar_id = bar_id;
  k._pad   = 0;
  return k;
}

/* Section: Session lifecycle */

//------------------------------------------------------------------------------
void BARProgram::PopulateBarConfigMap(
    uint64_t seid, const std::shared_ptr<pfcp::pfcp_bar>& bar, uint64_t flags) {
  if (!bar || !bar_config_map_) return;
  struct pfcp_bar bpf_bar;
  ConvertBar(*bar, bpf_bar);
  bar_map_key key = MakeKey(seid, bpf_bar.bar_id);
  int ret         = bar_config_map_->Update(key, bpf_bar, flags);
  if (ret != 0)
    Logger::upf_app().error(
        "BARProgram: config map update failed SEID=%" PRIu64
        " BAR_ID=%u ret=%d",
        seid, bpf_bar.bar_id, ret);
}

//------------------------------------------------------------------------------
void BARProgram::InitBarStateMap(uint64_t seid, uint32_t bar_id) {
  if (!bar_state_map_) return;
  bar_map_key key = MakeKey(seid, bar_id);
  bar_state_t state{};
  int ret = bar_state_map_->Update(key, state, BPF_NOEXIST);
  if (ret != 0 && ret != -EEXIST)
    Logger::upf_app().warn(
        "BARProgram: state map init failed SEID=%" PRIu64 " BAR_ID=%u ret=%d",
        seid, bar_id, ret);
}

//------------------------------------------------------------------------------
void BARProgram::Setup(
    uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_bar>>& bars) {
  for (const auto& bar : bars) {
    if (!bar) continue;
    PopulateBarConfigMap(seid, bar, BPF_ANY);
    InitBarStateMap(seid, bar->bar_id.second.bar_id);
  }
}

//------------------------------------------------------------------------------
void BARProgram::Update(
    uint64_t seid, const std::shared_ptr<pfcp::pfcp_bar>& bar) {
  if (!bar) return;
  PopulateBarConfigMap(seid, bar, BPF_EXIST);
}

//------------------------------------------------------------------------------
void BARProgram::Remove(uint64_t seid, uint32_t bar_id) {
  bar_map_key key = MakeKey(seid, bar_id);
  if (bar_config_map_) bar_config_map_->Remove(key);
  if (bar_state_map_) bar_state_map_->Remove(key);
}

//------------------------------------------------------------------------------
void BARProgram::TearDown(
    uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_bar>>& bars) {
  for (const auto& bar : bars) {
    if (!bar) continue;
    Remove(seid, bar->bar_id.second.bar_id);
  }
}

//------------------------------------------------------------------------------
bool BARProgram::ReadBarState(
    uint64_t seid, uint32_t bar_id, bar_state_t& out) const {
  if (!bar_state_map_) return false;
  bar_map_key key = MakeKey(seid, bar_id);
  return bar_state_map_->Lookup(key, &out) == 0;
}

//------------------------------------------------------------------------------
void BARProgram::ConvertBar(
    const pfcp::pfcp_bar& bar, struct pfcp_bar& bpf_bar) {
  bpf_bar = {};

  bpf_bar.bar_id = bar.bar_id.second.bar_id;

  if (bar.suggested_buffering_packets_count.first)
    bpf_bar.suggested_buffering_packets_count.packet_count =
        bar.suggested_buffering_packets_count.second.packet_count;

  if (bar.downlink_data_notification_delay.first)
    bpf_bar.dl_data_notification_delay.delay_value =
        bar.downlink_data_notification_delay.second.delay_value;
}