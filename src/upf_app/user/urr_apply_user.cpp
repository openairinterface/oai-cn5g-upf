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
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 §8.2.54 URR ID
 */
// clang-format on

#include "urr_apply_user.h"
#include <bpf/libbpf.h>
#include <cerrno>
#include <stdexcept>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "logger.hpp"
#include "upf_xdp_limits.h"
#include "utils/bpf_utils.hpp"

using namespace oai::utils::bpf;

//------------------------------------------------------------------------------
void URRProgram::ConfigureMaps(struct xdp_urr_apply_kern_c* skel) {
  if (!skel) {
    Logger::upf_app().error("Null skeleton in URRProgram::ConfigureMaps");
    return;
  }

  bool ok = true;

  /* urr_maps.h -- runtime-sized maps */
  ok &= ConfigureMapMaxEntries(
      skel->maps.urr_volume_counters_map, "urr_volume_counters_map",
      upf::GetMaxPduSessions());

  ok &= ConfigureMapMaxEntries(
      skel->maps.urr_config_map, "urr_config_map", upf::GetMaxPduSessions());

  /* urr_report_ringbuf_map: fixed size (256 KB) -- no runtime configuration. */

  if (!ok) {
    Logger::upf_app().error(
        "One or more map configurations failed for URRProgram.");
    throw std::runtime_error("URRProgram map configuration failed");
  }

  /* rodata: MAX_PDU_SESSIONS */
  if (skel->rodata) skel->rodata->MAX_PDU_SESSIONS = upf::GetMaxPduSessions();
}

//------------------------------------------------------------------------------
URRProgram::URRProgram() : BPFProgram() {
  Logger::upf_app().info("Initializing URR XDP Program...");

  auto open_fn = [this]() -> xdp_urr_apply_kern_c* {
    struct xdp_urr_apply_kern_c* s = xdp_urr_apply_kern_c__open();
    if (!s) {
      Logger::upf_app().error("Failed to open xdp_urr_apply skeleton");
      return nullptr;
    }
    // Configure maps and rodata before skeleton is loaded
    this->ConfigureMaps(s);
    // Store skeleton pointer -- available from this point onwards
    skeleton_ = s;
    return s;
  };

  lifecycle_ = std::make_shared<UrrProgramLifeCycle>(
      open_fn,
      /* load    */ xdp_urr_apply_kern_c__load,
      /* attach  */ xdp_urr_apply_kern_c__attach,
      /* destroy */ xdp_urr_apply_kern_c__destroy);
}

//------------------------------------------------------------------------------
void URRProgram::Setup() {
  /*
   * lifecycle_->open() is idempotent: if UPF_XDPProgram already called it
   * (to get the bpf_object for ShareMaps before loading), this returns the
   * cached skeleton with no side effects.
   */
  skeleton_ = lifecycle_->open();
  InitializeMaps();
  lifecycle_->load();
  Logger::upf_app().debug("URRProgram: loaded (no attach -- stage program)");
}

//------------------------------------------------------------------------------
void URRProgram::TearDown() {
  lifecycle_->tearDown();
}

//------------------------------------------------------------------------------
void URRProgram::InitializeMaps() {
  maps_    = std::make_shared<BPFMaps>(lifecycle_->getBPFSkeleton()->skeleton);
  auto get = [&](const char* name) {
    return std::make_shared<BPFMap>(maps_->GetMap(name));
  };
  /* urr_maps.h */
  urr_volume_counters_map_ = get("urr_volume_counters_map");
  urr_config_map_          = get("urr_config_map");
  urr_report_ringbuf_map_  = get("urr_report_ringbuf_map");
}

//------------------------------------------------------------------------------
struct bpf_object* URRProgram::GetBpfObject() const {
  return skeleton_ ? skeleton_->obj : nullptr;
}

//------------------------------------------------------------------------------
struct bpf_object_skeleton* URRProgram::GetSkeleton() const {
  return skeleton_ ? skeleton_->skeleton : nullptr;
}

//------------------------------------------------------------------------------
struct bpf_program* URRProgram::GetXdpProgram() const {
  return skeleton_ ? skeleton_->progs.urr_apply : nullptr;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMaps> URRProgram::GetMaps() const {
  return maps_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> URRProgram::GetUrrConfigMap() const {
  return urr_config_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> URRProgram::GetUrrVolumeMap() const {
  return urr_volume_counters_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> URRProgram::GetUrrReportRingbuf() const {
  return urr_report_ringbuf_map_;
}

//------------------------------------------------------------------------------
/*
 * TODO(fmessaoudi): See TODO in n3_entry_user.cpp -- GetMapCount() ownership.
 */
size_t URRProgram::GetMapCount() const {
  return maps_ ? maps_->GetMapCount() : 0;
}

//------------------------------------------------------------------------------
void URRProgram::ConvertUrr(
    const pfcp::pfcp_urr& urr, struct pfcp_urr& bpf_urr) {
  bpf_urr        = {};
  bpf_urr.urr_id = urr.urr_id.second.urr_id;
  if (urr.reporting_triggers.first) {
    bpf_urr.reporting_triggers.volth =
        urr.reporting_triggers.second.volth ? 1 : 0;
    bpf_urr.reporting_triggers.volqu =
        urr.reporting_triggers.second.volqu ? 1 : 0;
    bpf_urr.reporting_triggers.timth =
        urr.reporting_triggers.second.timth ? 1 : 0;
    bpf_urr.reporting_triggers.timqu =
        urr.reporting_triggers.second.timqu ? 1 : 0;
    bpf_urr.reporting_triggers.perio =
        urr.reporting_triggers.second.perio ? 1 : 0;
    bpf_urr.reporting_triggers.start =
        urr.reporting_triggers.second.start ? 1 : 0;
    bpf_urr.reporting_triggers.stop =
        urr.reporting_triggers.second.stop ? 1 : 0;
    bpf_urr.reporting_triggers.droth =
        urr.reporting_triggers.second.droth ? 1 : 0;
  }
  if (urr.volume_threshold.first) {
    bpf_urr.volume_threshold.total_volume =
        urr.volume_threshold.second.total_volume;
    bpf_urr.volume_threshold.uplink_volume =
        urr.volume_threshold.second.uplink_volume;
    bpf_urr.volume_threshold.downlink_volume =
        urr.volume_threshold.second.downlink_volume;
  }
  if (urr.volume_quota.first) {
    bpf_urr.volume_quota.total_volume  = urr.volume_quota.second.total_volume;
    bpf_urr.volume_quota.uplink_volume = urr.volume_quota.second.uplink_volume;
    bpf_urr.volume_quota.downlink_volume =
        urr.volume_quota.second.downlink_volume;
  }
  if (urr.measurement_period.first)
    bpf_urr.measurement_period.measurement_period =
        static_cast<uint64_t>(
            urr.measurement_period.second.measurement_period) *
        1000000000ULL;
  if (urr.time_threshold.first)
    bpf_urr.time_threshold.time_threshold =
        static_cast<uint64_t>(urr.time_threshold.second.time_threshold) *
        1000000000ULL;
  if (urr.monitoring_time.first)
    bpf_urr.monitoring_time.monitoring_time =
        static_cast<uint64_t>(urr.monitoring_time.second.monitoring_time) *
        1000000000ULL;
  if (urr.dropped_dl_traffic_threshold.first) {
    const auto& ddth = urr.dropped_dl_traffic_threshold.second;
    bpf_urr.dropped_dl_traffic_threshold.flags = 0;
    if (ddth.dlpa) {
      bpf_urr.dropped_dl_traffic_threshold.flags |= DDTH_FLAG_DLPA;
      bpf_urr.dropped_dl_traffic_threshold.downlink_packets =
          ddth.downlink_packets;
    }
    if (ddth.dlby) {
      bpf_urr.dropped_dl_traffic_threshold.flags |= DDTH_FLAG_DLBY;
      bpf_urr.dropped_dl_traffic_threshold.number_of_bytes_of_downlink_data =
          ddth.number_of_bytes_of_downlink_data;
    }
  }
}

//------------------------------------------------------------------------------
urr_map_key URRProgram::MakeKey(uint64_t seid, uint32_t urr_id) {
  urr_map_key k;
  k.seid   = seid;
  k.urr_id = urr_id;
  k._pad   = 0;
  return k;
}

//------------------------------------------------------------------------------
void URRProgram::PopulateUrrConfigMap(
    uint64_t seid, const std::shared_ptr<pfcp::pfcp_urr>& ie, uint64_t flags) {
  if (!ie || !urr_config_map_) return;
  struct pfcp_urr bpf_urr;
  ConvertUrr(*ie, bpf_urr);
  urr_map_key key = MakeKey(seid, bpf_urr.urr_id);
  int ret         = urr_config_map_->Update(key, bpf_urr, flags);
  if (ret != 0) {
    Logger::upf_app().error(
        "URRProgram: config map update failed SEID=%" PRIu64
        " URR_ID=%u ret=%d",
        seid, bpf_urr.urr_id, ret);
  } else {
    __u16 t;
    __builtin_memcpy(&t, &bpf_urr.reporting_triggers, sizeof(t));
    Logger::upf_app().debug(
        "URRProgram: config map updated SEID=%" PRIu64
        " URR_ID=%u triggers=0x%04x",
        seid, bpf_urr.urr_id, static_cast<unsigned>(t));
  }
}

//------------------------------------------------------------------------------
void URRProgram::InitUrrVolumeMap(uint64_t seid, uint32_t urr_id) {
  urr_map_key key = MakeKey(seid, urr_id);
  urr_volume_t zero{};
  if (!urr_volume_counters_map_) return;
  int ret = urr_volume_counters_map_->Update(key, zero, BPF_NOEXIST);
  if (ret != 0 && ret != -EEXIST)
    Logger::upf_app().warn(
        "URRProgram: volume map init failed SEID=%" PRIu64 " URR_ID=%u ret=%d",
        seid, urr_id, ret);
}

//------------------------------------------------------------------------------
void URRProgram::Setup(
    uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_urr>>& urrs) {
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
  PopulateUrrConfigMap(seid, urr, BPF_EXIST);
}

//------------------------------------------------------------------------------
void URRProgram::Remove(uint64_t seid, uint32_t urr_id) {
  urr_map_key key = MakeKey(seid, urr_id);
  if (urr_config_map_) urr_config_map_->Remove(key);
  if (urr_volume_counters_map_) urr_volume_counters_map_->Remove(key);
}

//------------------------------------------------------------------------------
void URRProgram::TearDown(
    uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_urr>>& urrs) {
  for (const auto& urr : urrs) {
    if (!urr) continue;
    Remove(seid, urr->urr_id.second.urr_id);
  }
}

//------------------------------------------------------------------------------
bool URRProgram::ReadVolumeCounters(
    uint64_t seid, uint32_t urr_id, urr_volume_t& out) const {
  urr_map_key key = MakeKey(seid, urr_id);
  if (!urr_volume_counters_map_) return false;
  return urr_volume_counters_map_->Lookup(key, &out) == 0;
}
