/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef BAR_APPLY_USER_H_
#define BAR_APPLY_USER_H_

#include <ProgramLifeCycle.hpp>
#include <linux/bpf.h>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>
#include <xdp_bar_apply_skel.h>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "BPFProgram.h"
#include "upf_network_config.h"
#include <bar_types.h>
#include <pfcp_bar.h>
#include <pfcp_session.hpp>

class BPFMaps;
class BPFMap;

using BarProgramLifeCycle = ProgramLifeCycle<xdp_bar_apply_kern_c>;

/**
 * @typedef bar_state_t
 * @brief Per-BAR runtime buffering state maintained by the data plane.
 *
 * An alias of the kernel `struct bar_state` (bar_types.h), so that the XDP
 * and userspace layouts cannot differ.
 *
 * Initialised with BPF_NOEXIST on session creation so that existing state
 * is preserved across session modifications.
 */
using bar_state_t = struct bar_state;

/* --------------------------------------------------------------------------
 * Map-value layout assertions (bar_config_map / bar_state_map).
 * The kernel and userspace views of these structs must match exactly. A size
 * or offset mismatch would not be caught at load time and would silently
 * corrupt the datapath state.
 * ------------------------------------------------------------------------ */
static_assert(sizeof(struct bar_config) == 8, "bar_config must stay 8 bytes");
static_assert(offsetof(struct bar_config, bar_id) == 0, "bar_config.bar_id @0");
static_assert(
    offsetof(struct bar_config, suggested_buf_pkt_cnt) == 4,
    "bar_config.suggested_buf_pkt_cnt @4");
static_assert(
    offsetof(struct bar_config, dl_notification_delay_50ms) == 6,
    "bar_config.dl_notification_delay_50ms @6");
static_assert(
    offsetof(struct bar_config, notify_cp) == 7, "bar_config.notify_cp @7");

static_assert(sizeof(struct bar_state) == 16, "bar_state must stay 16 bytes");
static_assert(alignof(struct bar_state) == 8, "bar_state must stay 8-aligned");
static_assert(
    offsetof(struct bar_state, notify_epoch_ns) == 0,
    "bar_state.notify_epoch_ns @0 (64-bit __sync_* operand)");
static_assert(
    offsetof(struct bar_state, buffered_pkt_count) == 8,
    "bar_state.buffered_pkt_count @8");
static_assert(
    offsetof(struct bar_state, notification_sent) == 12,
    "bar_state.notification_sent @12");

/**
 * @class BARProgram
 * @brief Manages the xdp_bar_apply XDP program lifecycle.
 *
 * Follows the same constructor/Setup/TearDown/InitializeMaps pattern as
 * SessionLookupIPProgram. Instantiated by UPF_XDPProgram only when
 * flags.enable_bar is set.
 *
 * Lifecycle (orchestrated by UPF_XDPProgram):
 *   1. Constructor  -- creates lifecycle_, does NOT open skeleton.
 *   2. UPF_XDPProgram calls GetLifeCycle()->open() before ShareMaps().
 *   3. UPF_XDPProgram::ShareMaps(primary, this) -- reuse_fd for shared maps.
 *   4. Setup()      -- InitializeMaps() + load() (no attach, no link).
 *   5. TearDown()   -- lifecycle_->tearDown().
 */
class BARProgram : public BPFProgram {
 public:
  /**
   * @brief Fixed size of xskmap, i.e. the most N6 RX queues DL buffering can
   *        capture from (one AF_XDP socket per queue, indexed by queue id).
   *
   * Fixed rather than sized from the NIC: the map is created at load, before
   * anything reads the queue count, and 64 slots cost nothing. The AF_XDP
   * consumer refuses to start on an N6 with more RX queues than this.
   */
  static constexpr uint32_t kXskMapMaxEntries = 64;

  /** @brief Constructor -- creates lifecycle_, does NOT open skeleton. */
  BARProgram();

  /** @brief Destructor. */
  virtual ~BARProgram() = default;

  /**
   * @brief Initialize maps and load the XDP program into the kernel.
   *
   * Order: lifecycle_->open() (idempotent) -> InitializeMaps() -> load().
   * Must be called AFTER UPF_XDPProgram::ShareMaps().
   * No attach() or link() -- stage program, reached via tail call only.
   */
  void Setup();

  /**
   * @brief Unload the XDP program.
   *
   * Delegates to lifecycle_->tearDown().
   * @note Distinct from TearDown(seid, bars) which removes session map entries.
   */
  void TearDown();

  /**
   * @brief Returns the lifecycle for external orchestration.
   *
   * UPF_XDPProgram uses this to call open() before ShareMaps().
   */
  std::shared_ptr<BarProgramLifeCycle> GetLifeCycle() const {
    return lifecycle_;
  }

  /** @brief Returns the underlying bpf_object for map sharing. */
  struct bpf_object* GetBpfObject() const;

  /** @brief Returns the raw bpf_object_skeleton pointer. */
  struct bpf_object_skeleton* GetSkeleton() const;

  /**
   * @brief Returns the xdp_program* for insertion into tail_call_progs_map.
   *
   * Called by UPF_XDPProgram::InsertProgramSlot(PROG_BAR_APPLY, ...).
   */
  struct bpf_program* GetXdpProgram() const;

  /** @brief Returns the container of all maps in this skeleton. */
  std::shared_ptr<BPFMaps> GetMaps() const;

  /** @name Direct map accessors (bar_maps.h) */
  ///@{
  std::shared_ptr<BPFMap> GetBarConfigMap() const;
  std::shared_ptr<BPFMap> GetBarStateMap() const;
  std::shared_ptr<BPFMap> GetBarDdnRingbuf() const;
  /** @brief xskmap: N6 RX queue id -> AF_XDP socket fd (XskConsumer). */
  std::shared_ptr<BPFMap> GetXskMap() const;
  ///@}

  /** @brief Returns the number of maps in this skeleton. */
  size_t GetMapCount() const;

  // ==========================================================================
  // Session lifecycle (called by SessionProgramManager)
  // ==========================================================================

  /**
   * @brief Configure the session BAR.
   *
   * Populates bar_config_map and initialises bar_state_map (BPF_NOEXIST).
   *
   * The maps hold one BAR per session: extra BARs are logged and skipped.
   * @p fars gives the NOCP bit, which the BAR IE does not carry.
   *
   * @param seid  PFCP session identifier.
   * @param bars  BAR IEs from PFCP Session Establishment Request.
   * @param fars  FARs of the same session (source of the NOCP bit).
   */
  void Setup(
      uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_bar>>& bars,
      const std::vector<std::shared_ptr<pfcp::pfcp_far>>& fars);

  /**
   * @brief Configure a session that buffers without a BAR.
   *
   * A BAR is optional (TS 29.244 §7.5.2.6), but the XDP BAR program drops
   * packets of a session with no bar_config. So write a default one, with
   * notify_cp set if a BUFF FAR has NOCP. (DeriveNotifyCp() skips FARs with
   * no BAR ID, so it cannot be used here.)
   *
   * @param seid  PFCP session identifier.
   * @param fars  FARs of the session (source of the BUFF and NOCP bits).
   */
  void SetupWithoutBar(
      uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_far>>& fars);

  /**
   * @brief Update a single BAR for an existing session.
   *
   * Overwrites the config entry; bar_state_map is NOT touched so that DDN
   * suppression state and buffered packet count are preserved.
   *
   * @param seid  PFCP session identifier.
   * @param bar   Updated BAR IE from PFCP Session Modification Request.
   * @param fars  FARs of the same session (source of the NOCP bit).
   */
  void Update(
      uint64_t seid, const std::shared_ptr<pfcp::pfcp_bar>& bar,
      const std::vector<std::shared_ptr<pfcp::pfcp_far>>& fars);

  /**
   * @brief Remove the session BAR from all maps.
   *
   * Both maps are keyed by SEID alone, so @p bar_id is used for logging only.
   *
   * @param seid    PFCP session identifier.
   * @param bar_id  BAR identifier to remove.
   */
  void Remove(uint64_t seid, uint32_t bar_id);

  /**
   * @brief Tear down all BARs for a session on deletion.
   * @param seid  PFCP session identifier.
   * @param bars  BARs to remove.
   */
  void TearDown(
      uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_bar>>& bars);

  /**
   * @brief Populate bar_config_map for a single BAR (key: plain u64 SEID).
   * @param seid       PFCP session identifier.
   * @param bar        BAR IE to convert and write.
   * @param notify_cp  Whether a FAR referencing this BAR has NOCP set (see
   *                   DeriveNotifyCp); stored as bar_config.notify_cp, which
   *                   gates DDN emission in the XDP BAR program (§8.2.26).
   * @param flags      BPF_ANY / BPF_NOEXIST / BPF_EXIST.
   */
  void PopulateBarConfigMap(
      uint64_t seid, const std::shared_ptr<pfcp::pfcp_bar>& bar, bool notify_cp,
      uint64_t flags = BPF_ANY);

  /**
   * @brief Whether the CP asked to be notified for this BAR (NOCP, §8.2.26
   *        bit 3).
   *
   * NOCP is set on the FAR, not the BAR. Returns true iff a FAR that
   * references @p bar_id has apply_action.nocp set.
   *
   * @param bar_id  BAR ID of the BAR being programmed.
   * @param fars    FARs of the same PFCP session.
   */
  static bool DeriveNotifyCp(
      uint32_t bar_id,
      const std::vector<std::shared_ptr<pfcp::pfcp_far>>& fars);

  /**
   * @brief Initialise bar_state_map entry (BPF_NOEXIST: never overwrites).
   *
   * Keyed by the plain u64 SEID; @p bar_id is used for logging only.
   *
   * Keeps an existing entry, so a BAR update while the UE is idle does not
   * lose the buffering state; -EEXIST is normal.
   *
   * @warning This is not a reset. Use ResetBarState() to clear the latch.
   *
   * @param seid    PFCP session identifier.
   * @param bar_id  BAR identifier.
   */
  void InitBarStateMap(uint64_t seid, uint32_t bar_id);

  /**
   * @brief Clear the one-shot DDN latch for a session (overwrite, BPF_EXIST).
   *
   * Zeroes the existing entry, so the next idle period notifies again. It is
   * the only way to re-arm a session.
   *
   * It never creates an entry (BPF_EXIST): the session may already be gone,
   * and a new entry would never be deleted. Only call it for a session that
   * still exists. Never throws, since it runs during Session Modification.
   *
   * @param seid  PFCP session identifier.
   * @return true if an entry existed and was zeroed; false if there was no
   *         entry (nothing latched) or the write failed.
   */
  bool ResetBarState(uint64_t seid);

  /**
   * @brief Read current buffering state for a BAR.
   *
   * Keyed by the plain u64 SEID; @p bar_id is used for logging only.
   *
   * @param seid    PFCP session identifier.
   * @param bar_id  BAR identifier.
   * @param[out] state  Output state struct.
   * @return true if entry found.
   */
  bool ReadBarState(uint64_t seid, uint32_t bar_id, bar_state_t& state) const;

 private:
  /**
   * @brief Configure max_entries for all runtime-sized maps.
   *
   * Uses ConfigureMapMaxEntries(skel->maps.field, "name", size).
   * Called inside the open_fn lambda before the skeleton is returned.
   *
   * @param skel Opened (not yet loaded) skeleton.
   */
  void ConfigureMaps(struct xdp_bar_apply_kern_c* skel);

  /**
   * @brief Wrap skeleton map FDs in BPFMap objects after open.
   */
  void InitializeMaps();

  /**
   * @brief Translate a PFCP BAR IE into the bar_config_map value.
   * @param ie         BAR IE.
   * @param notify_cp  Pre-computed FAR->BAR NOCP join result (DeriveNotifyCp).
   * @param[out] cfg   Map value to fill.
   */
  static void ConvertBar(
      const pfcp::pfcp_bar& ie, bool notify_cp, struct bar_config& cfg);

  //----------------------------------------------------------------------------
  // Skeleton and lifecycle
  //----------------------------------------------------------------------------
  xdp_bar_apply_kern_c* skeleton_ = nullptr;
  std::shared_ptr<BarProgramLifeCycle> lifecycle_;

  //----------------------------------------------------------------------------
  // Maps (bar_maps.h)
  //----------------------------------------------------------------------------
  std::shared_ptr<BPFMaps> maps_;
  std::shared_ptr<BPFMap> bar_config_map_;
  std::shared_ptr<BPFMap> bar_state_map_;
  std::shared_ptr<BPFMap> bar_ddn_ringbuf_map_;
  std::shared_ptr<BPFMap> bar_xskmap_;
};

#endif /* BAR_APPLY_USER_H_ */
