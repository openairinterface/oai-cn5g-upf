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

  /* xskmap: fixed cap, one slot per N6 RX queue (XskConsumer). */
  ok &= ConfigureMapMaxEntries(skel->maps.xskmap, "xskmap", kXskMapMaxEntries);

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
  bar_xskmap_          = get("xskmap");
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
std::shared_ptr<BPFMap> BARProgram::GetXskMap() const {
  return bar_xskmap_;
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
   * True if any FAR that references this BAR has Apply Action NOCP (§8.2.26).
   * BUFF is not checked here; SetupWithoutBar() requires BUFF and NOCP.
   * TS 29.244 §8.2.26 allows NOCP only together with BUFF, so for a compliant
   * SMF both rules give the same result.
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
   * Downlink Data Notification Delay (§8.2.28): kept in the IE's unit (50 ms);
   * xdp_bar_apply multiplies by 50 000 000 ns.
   */
  if (bar.downlink_data_notification_delay.first)
    cfg.dl_notification_delay_50ms =
        bar.downlink_data_notification_delay.second.delay_value;
  /*
   * NOCP (Apply Action, §8.2.26) is carried by the FAR, not by the BAR IE, so
   * the caller derives it (DeriveNotifyCp) and it is only stored here. The XDP
   * BAR program emits no DDN when this is 0, so a FAR with BUFF but without
   * NOCP buffers silently.
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
  /* bar_config_map is keyed by SEID, the same key the XDP reader uses
   * (xdp_bar_apply_kern.c). */
  bar_config_map_->Update(seid, cfg, flags);
}

//------------------------------------------------------------------------------
void BARProgram::InitBarStateMap(uint64_t seid, uint32_t bar_id) {
  bar_state_t state{};
  if (!bar_state_map_) return;
  /*
   * BPF_NOEXIST keeps the live buffering state, so -EEXIST is normal: Setup()
   * runs on every Session Modification with a BAR. TryUpdate() because
   * Update() throws, which would abort the whole Session Modification.
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
   * Zero the entry. This re-arms the notification latch: the next DL packet
   * that reaches the XDP BAR program can submit a DDN again. BPF_EXIST,
   * not BPF_ANY: the session may already be gone, and creating its entry
   * would leak a map slot. -ENOENT means there is no entry to re-arm.
   * TryUpdate() for the same reason as in InitBarStateMap().
   */
  bar_state_t zeroed{};
  int ret = bar_state_map_->TryUpdate(seid, zeroed, BPF_EXIST);
  if (ret == 0) {
    Logger::upf_app().debug(
        "BARProgram: bar_state cleared SEID=%" PRIu64
        " -- notification latch re-armed",
        seid);
    return true;
  }
  if (ret == -ENOENT) {
    Logger::upf_app().debug(
        "BARProgram: no bar_state entry for SEID=%" PRIu64
        " -- no notification latch to re-arm, not creating one",
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
   * Only one BAR per UP SEID is supported: bar_config_map and bar_state_map
   * are keyed by SEID, and xdp_bar_apply looks the config up by SEID alone, so
   * a second BAR would silently overwrite the first (wrong bar_id / notify_cp).
   * Configure the first BAR and ignore the others, with an error log.
   */
  bool bar_configured = false;
  for (const auto& bar : bars) {
    if (!bar) continue;
    const uint32_t bar_id = bar->bar_id.second.bar_id;
    if (bar_configured) {
      Logger::upf_app().error(
          "BARProgram: SEID=%" PRIu64
          " presents %zu BARs but only one BAR per session is supported "
          "-- ignoring BAR_ID=%u (the first BAR stays configured)",
          seid, bars.size(), bar_id);
      continue;
    }
    /* NOCP comes from the FARs: the BAR IE has no Apply Action of its own. */
    const bool notify_cp = DeriveNotifyCp(bar_id, fars);
    Logger::upf_app().debug(
        "BARProgram: SEID=%" PRIu64
        " BAR_ID=%u notify_cp=%u (derived from %zu "
        "FAR(s))",
        seid, bar_id, notify_cp ? 1U : 0U, fars.size());
    PopulateBarConfigMap(seid, bar, notify_cp, BPF_ANY);
    InitBarStateMap(seid, bar_id);
    bar_configured = true;
  }
}

//------------------------------------------------------------------------------
void BARProgram::SetupWithoutBar(
    uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_far>>& fars) {
  if (!bar_config_map_) return;
  bool notify_cp = false;
  for (const auto& far : fars) {
    if (far && far->apply_action.buff && far->apply_action.nocp) {
      notify_cp = true;
      break;
    }
  }
  /* bar_id 0, no count limit, no delay: only the NOCP gate is configured. */
  struct bar_config cfg = {};
  cfg.notify_cp         = notify_cp ? 1 : 0;
  /* TryUpdate(), not Update(), for the same reason as InitBarStateMap(). */
  int ret = bar_config_map_->TryUpdate(seid, cfg, BPF_ANY);
  if (ret != 0) {
    Logger::upf_app().error(
        "BARProgram: default config map update failed SEID=%" PRIu64 " ret=%d",
        seid, ret);
    return;
  }
  Logger::upf_app().debug(
      "BARProgram: SEID=%" PRIu64 " has no BAR, default config notify_cp=%u",
      seid, notify_cp ? 1U : 0U);
  InitBarStateMap(seid, 0);
}

//------------------------------------------------------------------------------
void BARProgram::Remove(uint64_t seid) {
  /*
   * Teardown must be best-effort and non-throwing: a session that never
   * buffered has no bar_state entry, and -ENOENT there must not abort the
   * rest of the caller's cleanup. Erasing bar_state also removes the session's
   * notification latch, so no entry outlives the session.
   */
  if (bar_config_map_) bar_config_map_->TryRemove(seid);
  if (bar_state_map_) bar_state_map_->TryRemove(seid);
}
