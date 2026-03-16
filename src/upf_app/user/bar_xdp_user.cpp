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
 *              §8.2.57   BAR ID   §8.2.100  Suggested Buffering Packets Count
 *              §8.2.28   DL Data Notification Delay
 */
// clang-format on

/**
 * @file bar_xdp_user.cpp
 * @brief Implementation of BAR BPF map manager
 * @author OpenAirInterface, Franck Messaoudi
 * @date 2025 / 2026-03
 */

#include "bar_xdp_user.h"
#include <linux/bpf.h>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <wrappers/BPFMap.hpp>
#include "logger.hpp"

//------------------------------------------------------------------------------
BARProgram::BARProgram(
    std::shared_ptr<BPFMap> bar_config_map,
    std::shared_ptr<BPFMap> bar_state_map)
    : bar_config_map_(std::move(bar_config_map)),
      bar_state_map_(std::move(bar_state_map)) {
  if (!bar_config_map_ || !bar_state_map_) {
    throw std::invalid_argument("BARProgram: null BPFMap pointer");
  }
  Logger::upf_app().debug("BARProgram initialised");
}

//------------------------------------------------------------------------------
// static helpers
//------------------------------------------------------------------------------

bar_map_key BARProgram::MakeKey(uint64_t seid, uint32_t bar_id) {
  bar_map_key k;
  k.seid   = seid;
  k.bar_id = bar_id;
  k._pad   = 0;
  return k;
}

//------------------------------------------------------------------------------
// void BARProgram::ConvertBar(
//     const pfcp::pfcp_bar& bar, struct pfcp_bar& bpf_bar) {
//   std::memset(&bpf_bar, 0, sizeof(bpf_bar));

//   bpf_bar.bar_id = bar.bar_id.second.bar_id;

//   // Suggested Buffering Packets Count (TS 29.244 Section 8.2.50)
//   if (bar.suggested_buffering_packets_count.first) {
//     bpf_bar.suggested_buffering_packets_count.packet_count =
//         bar.suggested_buffering_packets_count.second.packet_count;
//   }

//   // DL Data Notification Delay (TS 29.244 Section 8.2.28) — in seconds
//   if (bar.dl_buffering_suggested_packet_count.first) {
//     bpf_bar.dl_data_notification_delay.delay_value = static_cast<uint8_t>(
//         bar.dl_buffering_suggested_packet_count.second.delay_value);
//   }
// }

//------------------------------------------------------------------------------
// Public interface
//------------------------------------------------------------------------------

void BARProgram::PopulateBarConfigMap(
    uint64_t seid, const std::shared_ptr<pfcp::pfcp_bar>& bar, uint64_t flags) {
  if (!bar) return;

  struct pfcp_bar bpf_bar;
  ConvertBar(*bar, bpf_bar);

  bar_map_key key = MakeKey(seid, bpf_bar.bar_id);
  int ret         = bar_config_map_->Update(key, bpf_bar, flags);
  if (ret != 0) {
    Logger::upf_app().error(
        "BAR config map update failed: SEID=%" PRIu64 " BAR_ID=%u ret=%d", seid,
        bpf_bar.bar_id, ret);
  } else {
    Logger::upf_app().debug(
        "BAR config map: SEID=%" PRIu64 " BAR_ID=%u ddn_delay=%us buf_cnt=%u",
        seid, bpf_bar.bar_id, bpf_bar.dl_data_notification_delay.delay_value,
        bpf_bar.suggested_buffering_packets_count.packet_count);
  }
}

//------------------------------------------------------------------------------
void BARProgram::InitBarStateMap(uint64_t seid, uint32_t bar_id) {
  bar_map_key key = MakeKey(seid, bar_id);
  bar_state_t state{};
  // BPF_NOEXIST: preserve existing DDN state across session updates
  int ret = bar_state_map_->Update(key, state, BPF_NOEXIST);
  if (ret != 0 && ret != -EEXIST) {
    Logger::upf_app().warn(
        "BAR state map init: SEID=%" PRIu64 " BAR_ID=%u ret=%d", seid, bar_id,
        ret);
  }
}

//------------------------------------------------------------------------------
void BARProgram::Setup(
    uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_bar>>& bars) {
  Logger::upf_app().debug(
      "BARProgram::Setup SEID=%" PRIu64 " count=%zu", seid, bars.size());
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
  Logger::upf_app().debug(
      "BARProgram::Update SEID=%" PRIu64 " BAR_ID=%u", seid,
      bar->bar_id.second.bar_id);
  // Update config only — bar_state_map (DDN state) is NOT touched
  PopulateBarConfigMap(seid, bar, BPF_EXIST);
}

//------------------------------------------------------------------------------
void BARProgram::Remove(uint64_t seid, uint32_t bar_id) {
  Logger::upf_app().debug(
      "BARProgram::Remove SEID=%" PRIu64 " BAR_ID=%u", seid, bar_id);
  bar_map_key key = MakeKey(seid, bar_id);
  bar_config_map_->Remove(key);
  bar_state_map_->Remove(key);
}

//------------------------------------------------------------------------------
void BARProgram::TearDown(
    uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_bar>>& bars) {
  Logger::upf_app().debug(
      "BARProgram::TearDown SEID=%" PRIu64 " count=%zu", seid, bars.size());
  for (const auto& bar : bars) {
    if (!bar) continue;
    Remove(seid, bar->bar_id.second.bar_id);
  }
}

//------------------------------------------------------------------------------
bool BARProgram::ReadBarState(
    uint64_t seid, uint32_t bar_id, bar_state_t& out) const {
  bar_map_key key = MakeKey(seid, bar_id);
  int ret         = bar_state_map_->Lookup(key, &out);
  if (ret != 0) {
    Logger::upf_app().warn(
        "BAR state read miss: SEID=%" PRIu64 " BAR_ID=%u", seid, bar_id);
    return false;
  }
  return true;
}
