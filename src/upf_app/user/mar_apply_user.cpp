/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "mar_apply_user.h"
#include <bpf/libbpf.h>
#include <stdexcept>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "logger.hpp"
#include "upf_xdp_limits.h"
#include "utils/bpf_utils.hpp"
#include "mar_types.h"

using namespace oai::utils::bpf;

//------------------------------------------------------------------------------
void MARProgram::ConfigureMaps(struct xdp_mar_apply_kern_c* skel) {
  if (!skel) {
    Logger::upf_app().error("Null skeleton in MARProgram::ConfigureMaps");
    return;
  }

  bool ok = true;

  /* mar_maps.h -- runtime-sized maps */
  ok &= ConfigureMapMaxEntries(
      skel->maps.mar_config_map, "mar_config_map", upf::GetMaxPduSessions());

  ok &= ConfigureMapMaxEntries(
      skel->maps.mar_access_state_map, "mar_access_state_map",
      upf::GetMaxPduSessions());

  if (!ok) {
    Logger::upf_app().error(
        "One or more map configurations failed for MARProgram.");
    throw std::runtime_error("MARProgram map configuration failed");
  }

  /* rodata: MAX_PDU_SESSIONS */
  if (skel->rodata) skel->rodata->MAX_PDU_SESSIONS = upf::GetMaxPduSessions();
}

//------------------------------------------------------------------------------
MARProgram::MARProgram() : BPFProgram() {
  Logger::upf_app().debug("Initializing MAR XDP Program ...");

  auto open_fn = [this]() -> xdp_mar_apply_kern_c* {
    struct xdp_mar_apply_kern_c* s = xdp_mar_apply_kern_c__open();
    if (!s) {
      Logger::upf_app().error("Failed to open xdp_mar_apply skeleton");
      return nullptr;
    }
    // Configure maps and rodata before skeleton is loaded
    this->ConfigureMaps(s);
    // Store skeleton pointer -- available from this point onwards
    skeleton_ = s;
    return s;
  };

  lifecycle_ = std::make_shared<MarProgramLifeCycle>(
      open_fn,
      /* load    */ xdp_mar_apply_kern_c__load,
      /* attach  */ xdp_mar_apply_kern_c__attach,
      /* destroy */ xdp_mar_apply_kern_c__destroy, "MARProgram");
}

//------------------------------------------------------------------------------
void MARProgram::Setup() {
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
void MARProgram::TearDown() {
  lifecycle_->tearDown();
}

//------------------------------------------------------------------------------
void MARProgram::InitializeMaps() {
  maps_    = std::make_shared<BPFMaps>(lifecycle_->getBPFSkeleton()->skeleton);
  auto get = [&](const char* name) {
    return std::make_shared<BPFMap>(maps_->GetMap(name));
  };
  /* mar_maps.h */
  mar_config_map_       = get("mar_config_map");
  mar_access_state_map_ = get("mar_access_state_map");
}

//------------------------------------------------------------------------------
struct bpf_object* MARProgram::GetBpfObject() const {
  return skeleton_ ? skeleton_->obj : nullptr;
}

//------------------------------------------------------------------------------
struct bpf_object_skeleton* MARProgram::GetSkeleton() const {
  return skeleton_ ? skeleton_->skeleton : nullptr;
}

//------------------------------------------------------------------------------
struct bpf_program* MARProgram::GetXdpProgram() const {
  return skeleton_ ? skeleton_->progs.mar_apply : nullptr;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMaps> MARProgram::GetMaps() const {
  return maps_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> MARProgram::GetMarConfigMap() const {
  return mar_config_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> MARProgram::GetMarAccessStateMap() const {
  return mar_access_state_map_;
}

//------------------------------------------------------------------------------
/*
 * TODO(fmessaoudi): See TODO in n3_entry_user.cpp -- GetMapCount() ownership.
 */
size_t MARProgram::GetMapCount() const {
  return maps_ ? maps_->GetMapCount() : 0;
}

//------------------------------------------------------------------------------
void MARProgram::ConvertMar(
    const pfcp::pfcp_mar& mar, struct pfcp_mar& bpf_mar) {
  bpf_mar        = {};
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

//------------------------------------------------------------------------------
mar_map_key MARProgram::MakeKey(uint64_t seid, uint32_t mar_id) {
  mar_map_key k;
  k.seid   = seid;
  k.mar_id = mar_id;
  k._pad   = 0;
  return k;
}

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
void MARProgram::InitMarAccessStateMap(uint64_t seid, uint32_t mar_id) {
  mar_map_key key = MakeKey(seid, mar_id);
  struct mar_access_state state {};
  if (!mar_access_state_map_) return;
  mar_access_state_map_->Update(key, state, BPF_NOEXIST);
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
