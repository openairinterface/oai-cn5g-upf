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
 *              §8.2.54  URR ID   §8.2.48  Volume Threshold   §8.2.46  Volume Quota
 */
// clang-format on

/**
 * @file urr_xdp_user.cpp
 * @brief Implementation of URR BPF map manager
 * @author OpenAirInterface, Franck Messaoudi
 * @date 2025 / 2026-03
 */

#include "urr_xdp_user.h"
#include <linux/bpf.h>
#include <cstring>
#include <stdexcept>
#include <wrappers/BPFMap.hpp>
#include "logger.hpp"

//------------------------------------------------------------------------------
URRProgram::URRProgram(
    std::shared_ptr<BPFMap> urr_config_map,
    std::shared_ptr<BPFMap> urr_volume_map)
    : urr_config_map_(std::move(urr_config_map)),
      urr_volume_map_(std::move(urr_volume_map)) {
  if (!urr_config_map_ || !urr_volume_map_) {
    throw std::invalid_argument("URRProgram: null BPFMap pointer");
  }
  Logger::upf_app().debug("URRProgram initialised");
}

//------------------------------------------------------------------------------
// static helpers
//------------------------------------------------------------------------------

urr_map_key URRProgram::MakeKey(uint64_t seid, uint32_t urr_id) {
  urr_map_key k;
  k.seid   = seid;
  k.urr_id = urr_id;
  k._pad   = 0;
  return k;
}

//------------------------------------------------------------------------------
// void URRProgram::ConvertUrr(
//     const pfcp::pfcp_urr& ie, struct pfcp_urr& bpf_urr) {
//   std::memset(&bpf_urr, 0, sizeof(bpf_urr));

//   bpf_urr.urr_id = ie.urr_id.second.urr_id;

//   // Reporting triggers bitmask (TS 29.244 Section 8.2.53)
//   // reporting_triggers is a struct of bitfields — accumulate into a u8
//   first,
//   // then assign to the BPF scalar field.
//   if (ie.reporting_triggers.first) {
//     const auto& t    = ie.reporting_triggers.second;
//     uint8_t triggers = 0;
//     if (t.volth) triggers |= URR_TRIGGER_VOLTH;
//     if (t.volqu) triggers |= URR_TRIGGER_VOLQU;
//     if (t.timth) triggers |= URR_TRIGGER_TIMTH;
//     if (t.timqu) triggers |= URR_TRIGGER_TIMQU;
//     if (t.perio) triggers |= URR_TRIGGER_PERIO;
//     if (t.start) triggers |= URR_TRIGGER_START;
//     if (t.stop)
//       triggers |= URR_TRIGGER_STOPT;  // field is 'stop' in 3gpp_29.244.h:625
//     if (t.droth) triggers |= URR_TRIGGER_DROTH;
//     bpf_urr.reporting_triggers = triggers;
//   }

//   // Volume Threshold (TS 29.244 Section 8.2.48)
//   if (ie.volume_threshold.first) {
//     const auto& vt = ie.volume_threshold.second;
//     if (vt.tovol) bpf_urr.volume_threshold.total_volume = vt.total_volume;
//     if (vt.ulvol) bpf_urr.volume_threshold.uplink_volume = vt.uplink_volume;
//     if (vt.dlvol) bpf_urr.volume_threshold.downlink_volume =
//     vt.downlink_volume;
//   }

//   // Volume Quota (TS 29.244 Section 8.2.46)
//   if (ie.volume_quota.first) {
//     const auto& vq = ie.volume_quota.second;
//     if (vq.tovol) bpf_urr.volume_quota.total_volume = vq.total_volume;
//     if (vq.ulvol) bpf_urr.volume_quota.uplink_volume = vq.uplink_volume;
//     if (vq.dlvol) bpf_urr.volume_quota.downlink_volume = vq.downlink_volume;
//   }

//   // Time Threshold (TS 29.244 Section 8.2.48) — stored in nanoseconds
//   if (ie.time_threshold.first) {
//     // PFCP IE carries seconds; convert to ns for the data plane
//     bpf_urr.time_threshold.time_threshold =
//         static_cast<uint64_t>(ie.time_threshold.second.time_threshold) *
//         1'000'000'000ULL;
//   }

//   // Measurement Period (TS 29.244 Section 8.2.72)
//   if (ie.measurement_period.first) {
//     bpf_urr.measurement_period.measurement_period =
//         static_cast<uint64_t>(ie.measurement_period.second.measurement_period)
//         * 1'000'000'000ULL;
//   }

//   // Monitoring Time (TS 29.244 Section 8.2.67) — absolute UNIX timestamp
//   if (ie.monitoring_time.first) {
//     bpf_urr.monitoring_time.monitoring_time =
//         static_cast<uint64_t>(ie.monitoring_time.second.monitoring_time) *
//         1'000'000'000ULL;
//   }
// }

//------------------------------------------------------------------------------
// Public interface
//------------------------------------------------------------------------------

void URRProgram::PopulateUrrConfigMap(
    uint64_t seid, const std::shared_ptr<pfcp::pfcp_urr>& ie, uint64_t flags) {
  if (!ie) return;

  struct pfcp_urr bpf_urr;
  ConvertUrr(*ie, bpf_urr);

  urr_map_key key = MakeKey(seid, bpf_urr.urr_id);
  int ret         = urr_config_map_->Update(key, bpf_urr, flags);
  // if (ret != 0) {
  //   Logger::upf_app().error(
  //       "URR config map update failed: SEID=%" PRIu64 " URR_ID=%u ret=%d",
  //       seid, bpf_urr.urr_id, ret);
  // } else {
  //   Logger::upf_app().debug(
  //       "URR config map: SEID=%" PRIu64 " URR_ID=%u triggers=0x%02x", seid,
  //       bpf_urr.urr_id, bpf_urr.reporting_triggers);
  // }
}

//------------------------------------------------------------------------------
void URRProgram::InitUrrVolumeMap(uint64_t seid, uint32_t urr_id) {
  urr_map_key key = MakeKey(seid, urr_id);
  urr_volume_t zero{};
  // BPF_NOEXIST: insert only if not present — preserves in-flight counters
  int ret = urr_volume_map_->Update(key, zero, BPF_NOEXIST);
  if (ret != 0 && ret != -EEXIST) {
    Logger::upf_app().warn(
        "URR volume map init: SEID=%" PRIu64 " URR_ID=%u ret=%d", seid, urr_id,
        ret);
  }
}

//------------------------------------------------------------------------------
void URRProgram::Setup(
    uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_urr>>& urrs) {
  Logger::upf_app().debug(
      "URRProgram::Setup SEID=%" PRIu64 " count=%zu", seid, urrs.size());
  for (const auto& urr : urrs) {
    if (!urr) continue;
    PopulateUrrConfigMap(seid, urr, BPF_ANY);
    InitUrrVolumeMap(seid, urr->urr_id.second.urr_id);
  }
}

//------------------------------------------------------------------------------
void URRProgram::Update(
    uint64_t seid, const std::shared_ptr<pfcp::pfcp_urr>& urr) {
  if (!urr) return;
  Logger::upf_app().debug(
      "URRProgram::Update SEID=%" PRIu64 " URR_ID=%u", seid,
      urr->urr_id.second.urr_id);
  // Update config; volume counters are preserved (BPF_NOEXIST semantics)
  PopulateUrrConfigMap(seid, urr, BPF_EXIST);
}

//------------------------------------------------------------------------------
void URRProgram::Remove(uint64_t seid, uint32_t urr_id) {
  Logger::upf_app().debug(
      "URRProgram::Remove SEID=%" PRIu64 " URR_ID=%u", seid, urr_id);
  urr_map_key key = MakeKey(seid, urr_id);
  urr_config_map_->Remove(key);
  urr_volume_map_->Remove(key);
}

//------------------------------------------------------------------------------
void URRProgram::TearDown(
    uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_urr>>& urrs) {
  Logger::upf_app().debug(
      "URRProgram::TearDown SEID=%" PRIu64 " count=%zu", seid, urrs.size());
  for (const auto& urr : urrs) {
    if (!urr) continue;
    Remove(seid, urr->urr_id.second.urr_id);
  }
}

//------------------------------------------------------------------------------
bool URRProgram::ReadVolumeCounters(
    uint64_t seid, uint32_t urr_id, urr_volume_t& out) const {
  urr_map_key key = MakeKey(seid, urr_id);
  int ret         = urr_volume_map_->Lookup(key, &out);
  if (ret != 0) {
    Logger::upf_app().warn(
        "URR volume read miss: SEID=%" PRIu64 " URR_ID=%u", seid, urr_id);
    return false;
  }
  return true;
}
