/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "bar_apply_user.h"
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
void BARProgram::ConfigureMaps(struct xdp_bar_apply_kern_c* skel) {
  if (!skel) {
    Logger::upf_app().error("Null skeleton in BARProgram::ConfigureMaps");
    return;
  }

  bool ok = true;

  /* bar_maps.h -- runtime-sized maps */
  ok &= ConfigureMapMaxEntries(
      skel->maps.bar_config_map, "bar_config_map", upf::GetMaxPduSessions());

  ok &= ConfigureMapMaxEntries(
      skel->maps.bar_state_map, "bar_state_map", upf::GetMaxPduSessions());

  /* bar_ddn_ringbuf_map: fixed size (64 KB) -- no runtime configuration. */

  if (!ok) {
    Logger::upf_app().error(
        "One or more map configurations failed for BARProgram.");
    throw std::runtime_error("BARProgram map configuration failed");
  }

  /* rodata: MAX_PDU_SESSIONS (bar_maps.h declares it) */
  if (skel->rodata) skel->rodata->MAX_PDU_SESSIONS = upf::GetMaxPduSessions();
}

//------------------------------------------------------------------------------
BARProgram::BARProgram() : BPFProgram() {
  Logger::upf_app().debug("Initializing BAR XDP Program ...");

  auto open_fn = [this]() -> xdp_bar_apply_kern_c* {
    struct xdp_bar_apply_kern_c* s = xdp_bar_apply_kern_c__open();
    if (!s) {
      Logger::upf_app().error("Failed to open xdp_bar_apply skeleton");
      return nullptr;
    }
    // Configure maps before skeleton is loaded
    this->ConfigureMaps(s);
    // Store skeleton pointer -- available from this point onwards
    skeleton_ = s;
    return s;
  };

  lifecycle_ = std::make_shared<BarProgramLifeCycle>(
      open_fn,
      /* load    */ xdp_bar_apply_kern_c__load,
      /* attach  */ xdp_bar_apply_kern_c__attach,
      /* destroy */ xdp_bar_apply_kern_c__destroy, "BARProgram");
}

//------------------------------------------------------------------------------
void BARProgram::Setup() {
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
void BARProgram::TearDown() {
  lifecycle_->tearDown();
}

//------------------------------------------------------------------------------
void BARProgram::InitializeMaps() {
  maps_    = std::make_shared<BPFMaps>(lifecycle_->getBPFSkeleton()->skeleton);
  auto get = [&](const char* name) {
    return std::make_shared<BPFMap>(maps_->GetMap(name));
  };
  /* bar_maps.h */
  bar_config_map_      = get("bar_config_map");
  bar_state_map_       = get("bar_state_map");
  bar_ddn_ringbuf_map_ = get("bar_ddn_ringbuf_map");
}

//------------------------------------------------------------------------------
struct bpf_object* BARProgram::GetBpfObject() const {
  return skeleton_ ? skeleton_->obj : nullptr;
}

//------------------------------------------------------------------------------
struct bpf_object_skeleton* BARProgram::GetSkeleton() const {
  return skeleton_ ? skeleton_->skeleton : nullptr;
}

//------------------------------------------------------------------------------
struct bpf_program* BARProgram::GetXdpProgram() const {
  return skeleton_ ? skeleton_->progs.bar_apply : nullptr;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMaps> BARProgram::GetMaps() const {
  return maps_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> BARProgram::GetBarConfigMap() const {
  return bar_config_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> BARProgram::GetBarStateMap() const {
  return bar_state_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> BARProgram::GetBarDdnRingbuf() const {
  return bar_ddn_ringbuf_map_;
}

//------------------------------------------------------------------------------
/*
 * TODO(fmessaoudi): See TODO in n3_entry_user.cpp -- GetMapCount() ownership.
 */
size_t BARProgram::GetMapCount() const {
  return maps_ ? maps_->GetMapCount() : 0;
}

//------------------------------------------------------------------------------
void BARProgram::ConvertBar(
    const pfcp::pfcp_bar& bar, struct pfcp_bar& bpf_bar) {
  bpf_bar        = {};
  bpf_bar.bar_id = bar.bar_id.second.bar_id;
  if (bar.suggested_buffering_packets_count.first)
    bpf_bar.suggested_buffering_packets_count.packet_count =
        bar.suggested_buffering_packets_count.second.packet_count;
  if (bar.downlink_data_notification_delay.first)
    bpf_bar.dl_data_notification_delay.delay_value =
        bar.downlink_data_notification_delay.second.delay_value;
}

//------------------------------------------------------------------------------
bar_map_key BARProgram::MakeKey(uint64_t seid, uint32_t bar_id) {
  bar_map_key k;
  k.seid   = seid;
  k.bar_id = bar_id;
  k._pad   = 0;
  return k;
}

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
  bar_map_key key = MakeKey(seid, bar_id);
  bar_state_t state{};
  if (!bar_state_map_) return;
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
  bar_map_key key = MakeKey(seid, bar_id);
  if (!bar_state_map_) return false;
  return bar_state_map_->Lookup(key, &out) == 0;
}
