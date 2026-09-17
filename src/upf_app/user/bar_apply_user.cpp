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
bool BARProgram::DeriveNotifyCp(
    uint32_t bar_id, const std::vector<std::shared_ptr<pfcp::pfcp_far>>& fars) {
  /*
   * §8.2.26 bit 3 (NOCP) lives on the FAR, not on the BAR: the CP asks to be
   * notified by setting Apply Action NOCP on the FAR that also carries BUFF
   * and references the BAR. Join FAR -> BAR by BAR ID (§8.2.57) and report
   * whether ANY referencing FAR asked for the notification.
   */
  for (const auto& far : fars) {
    if (!far) continue;
    if (!far->bar_id.first) continue; /* FAR references no BAR */
    if (static_cast<uint32_t>(far->bar_id.second.bar_id) != bar_id) continue;
    if (far->apply_action.nocp) return true;
  }
  return false;
}

//------------------------------------------------------------------------------
void BARProgram::ConvertBar(
    const pfcp::pfcp_bar& bar, bool notify_cp, struct bar_config& cfg) {
  cfg        = {};
  cfg.bar_id = bar.bar_id.second.bar_id;
  if (bar.suggested_buffering_packets_count.first)
    cfg.suggested_buf_pkt_cnt =
        bar.suggested_buffering_packets_count.second.packet_count;
  /*
   * DL Data Notification Delay (§8.2.28) is encoded in units of 50 ms.
   * Copy it verbatim -- converting to seconds would round every sub-second
   * delay (e.g. 1 = 50 ms) down to 0.
   */
  if (bar.downlink_data_notification_delay.first)
    cfg.dl_notification_delay_50ms =
        bar.downlink_data_notification_delay.second.delay_value;
  /*
   * NOCP (§8.2.26 bit 3) is carried by the FAR, not by the BAR IE, so it is
   * joined in by the caller (DeriveNotifyCp) and only stored here. The XDP
   * BAR program refuses to emit a DDN when this is 0, i.e. a BUFF-without-
   * NOCP FAR buffers silently.
   */
  cfg.notify_cp = notify_cp ? 1 : 0;
}

//------------------------------------------------------------------------------
void BARProgram::PopulateBarConfigMap(
    uint64_t seid, const std::shared_ptr<pfcp::pfcp_bar>& bar, bool notify_cp,
    uint64_t flags) {
  if (!bar || !bar_config_map_) return;
  struct bar_config cfg;
  ConvertBar(*bar, notify_cp, cfg);
  /* bar_config_map is keyed by the plain u64 SEID -- the same key the XDP
   * reader uses (xdp_bar_apply_kern.c). */
  int ret = bar_config_map_->Update(seid, cfg, flags);
  if (ret != 0)
    Logger::upf_app().error(
        "BARProgram: config map update failed SEID=%" PRIu64
        " BAR_ID=%u ret=%d",
        seid, cfg.bar_id, ret);
}

//------------------------------------------------------------------------------
void BARProgram::InitBarStateMap(uint64_t seid, uint32_t bar_id) {
  bar_state_t state{};
  if (!bar_state_map_) return;
  /*
   * Plain u64 SEID key; BPF_NOEXIST keeps any live buffering state intact.
   *
   * -EEXIST is the EXPECTED outcome, not an error: Setup() re-runs on every
   * Session Modification that carries a BAR, and the XDP datapath itself
   * creates the entry (also with BPF_NOEXIST) on its missing-state path, so
   * "already there" is a normal race. Preserving the live latch is exactly
   * what BPF_NOEXIST is for -- log it at debug and carry on.
   *
   * TryUpdate() (not Update()) on purpose: Update() throws on ANY non-zero
   * result, which would propagate out of BARProgram::Setup() into
   * SessionProgramManager::ModifyPipeline() -- which re-throws -- aborting
   * the modification BEFORE the PDR/FAR programming loop that carries the
   * BUFFER->FORWARD paging release.
   */
  int ret = bar_state_map_->TryUpdate(seid, state, BPF_NOEXIST);
  if (ret == -EEXIST) {
    Logger::upf_app().debug(
        "BARProgram: state map entry already present SEID=%" PRIu64
        " BAR_ID=%u -- live buffering state preserved",
        seid, bar_id);
  } else if (ret != 0) {
    Logger::upf_app().error(
        "BARProgram: state map init failed SEID=%" PRIu64 " BAR_ID=%u ret=%d",
        seid, bar_id, ret);
  }
}

//------------------------------------------------------------------------------
bool BARProgram::ResetBarState(uint64_t seid) {
  if (!bar_state_map_) return false;
  /*
   * The counterpart of InitBarStateMap(): that one is BPF_NOEXIST and can
   * therefore never clear a latched notification, this one overwrites the
   * live entry with a zeroed bar_state -- notify_epoch_ns back to
   * NOTIFY_FREE, notification_sent mirror cleared, counter reset -- so the
   * next idle burst notifies again.
   *
   * BPF_EXIST, not BPF_ANY: a reset must never CREATE an entry. The UPF-T4
   * consumer re-arms by UP-SEID and may be holding a SEID whose session is
   * already gone; creating it there would leak a map slot that nothing
   * deletes again. -ENOENT simply means there is no latch to clear.
   *
   * TryUpdate() (not Update()) for the same reason as in InitBarStateMap():
   * Update() throws on any non-zero result, and this runs on the Session
   * Modification path that carries the BUFFER->FORWARD paging release.
   */
  bar_state_t zeroed{};
  int ret = bar_state_map_->TryUpdate(seid, zeroed, BPF_EXIST);
  if (ret == 0) {
    Logger::upf_app().debug(
        "BARProgram: bar_state cleared SEID=%" PRIu64
        " -- DDN one-shot re-armed",
        seid);
    return true;
  }
  if (ret == -ENOENT) {
    Logger::upf_app().debug(
        "BARProgram: no bar_state entry for SEID=%" PRIu64
        " -- nothing latched, not creating one",
        seid);
    return false;
  }
  Logger::upf_app().error(
      "BARProgram: bar_state reset failed SEID=%" PRIu64 " ret=%d", seid, ret);
  return false;
}

//------------------------------------------------------------------------------
void BARProgram::Setup(
    uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_bar>>& bars,
    const std::vector<std::shared_ptr<pfcp::pfcp_far>>& fars) {
  /*
   * Phase 1 supports exactly ONE BAR per UP-SEID: bar_config_map and
   * bar_state_map are keyed by the plain u64 SEID and xdp_bar_apply looks the
   * config up by SEID alone, so a second BAR would silently overwrite the
   * first (wrong bar_id / notify_cp on the wire). Arm the first BAR and
   * reject the rest loudly instead of collapsing them.
   */
  bool armed = false;
  for (const auto& bar : bars) {
    if (!bar) continue;
    const uint32_t bar_id = bar->bar_id.second.bar_id;
    if (armed) {
      Logger::upf_app().error(
          "BARProgram: SEID=%" PRIu64
          " presents %zu BARs but only one BAR per session is supported "
          "-- rejecting BAR_ID=%u (armed BAR left untouched)",
          seid, bars.size(), bar_id);
      continue;
    }
    /* FAR -> BAR NOCP join: the BAR IE has no Apply Action of its own. */
    const bool notify_cp = DeriveNotifyCp(bar_id, fars);
    Logger::upf_app().debug(
        "BARProgram: SEID=%" PRIu64
        " BAR_ID=%u notify_cp=%u (derived from %zu "
        "FAR(s))",
        seid, bar_id, notify_cp ? 1U : 0U, fars.size());
    PopulateBarConfigMap(seid, bar, notify_cp, BPF_ANY);
    InitBarStateMap(seid, bar_id);
    armed = true;
  }
}

//------------------------------------------------------------------------------
void BARProgram::Update(
    uint64_t seid, const std::shared_ptr<pfcp::pfcp_bar>& bar,
    const std::vector<std::shared_ptr<pfcp::pfcp_far>>& fars) {
  if (!bar) return;
  const bool notify_cp = DeriveNotifyCp(bar->bar_id.second.bar_id, fars);
  PopulateBarConfigMap(seid, bar, notify_cp, BPF_EXIST);
}

//------------------------------------------------------------------------------
void BARProgram::Remove(uint64_t seid, uint32_t bar_id) {
  (void) bar_id; /* both maps are keyed by SEID alone */
  /*
   * Teardown must be best-effort and non-throwing: a session that never
   * buffered has no bar_state entry, and -ENOENT there must not abort the
   * rest of the caller's cleanup. Erasing bar_state here is what makes a
   * re-established SEID start with a clear DDN latch.
   */
  if (bar_config_map_) bar_config_map_->TryRemove(seid);
  if (bar_state_map_) bar_state_map_->TryRemove(seid);
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
  (void) bar_id; /* bar_state_map is keyed by SEID alone */
  if (!bar_state_map_) return false;
  return bar_state_map_->Lookup(seid, &out) == 0;
}
