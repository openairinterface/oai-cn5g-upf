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
 * Deliberately an alias of the kernel-side `struct bar_state`
 * (kernel/include/bar_types.h) rather than a hand-written mirror: the map
 * value layout is shared ABI and must never drift between the XDP reader and
 * the userspace writer.
 *
 * Initialised with BPF_NOEXIST on session creation so that existing state
 * is preserved across session modifications.
 */
using bar_state_t = struct bar_state;

/* --------------------------------------------------------------------------
 * Shared map-value ABI assertions (bar_config_map / bar_state_map).
 * These guard the kernel <-> userspace lockstep required by UPF-T1: the XDP
 * verifier re-reads the value layout at load time, so any size/offset drift
 * here is a silent datapath corruption.
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
   * Both maps are keyed by the plain u64 UP-SEID, which holds exactly ONE
   * BAR per session. If @p bars carries more than one BAR the extras are
   * logged as an error and skipped -- they are never allowed to overwrite
   * the armed entry.
   *
   * @p fars is needed for the FAR->BAR NOCP join: the BAR IE does not carry
   * the Apply Action, so bar_config.notify_cp is derived from the FAR(s) of
   * the same session that reference this BAR ID (see DeriveNotifyCp).
   *
   * @param seid  PFCP session identifier.
   * @param bars  BAR IEs from PFCP Session Establishment Request.
   * @param fars  FARs of the same session (source of the NOCP bit).
   */
  void Setup(
      uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_bar>>& bars,
      const std::vector<std::shared_ptr<pfcp::pfcp_far>>& fars);

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
   * @param notify_cp  Result of the FAR->BAR NOCP join for this BAR; stored
   *                   as bar_config.notify_cp and used by the XDP BAR
   *                   program to gate DDN emission (§8.2.26).
   * @param flags      BPF_ANY / BPF_NOEXIST / BPF_EXIST.
   */
  void PopulateBarConfigMap(
      uint64_t seid, const std::shared_ptr<pfcp::pfcp_bar>& bar, bool notify_cp,
      uint64_t flags = BPF_ANY);

  /**
   * @brief FAR -> BAR NOCP join (§8.2.26 bit 3).
   *
   * The BAR IE carries no Apply Action, so the "notify the CP" intent lives
   * on the FAR side. Returns true iff at least one FAR of the session
   * references @p bar_id (FAR.bar_id IE, §8.2.57) AND has
   * apply_action.nocp set.
   *
   * @param bar_id  BAR ID of the BAR being programmed.
   * @param fars    FARs of the same PFCP session.
   */
  static bool DeriveNotifyCp(
      uint32_t bar_id,
      const std::vector<std::shared_ptr<pfcp::pfcp_far>>& fars);

  /**
   * @brief Initialise bar_state_map entry (BPF_NOEXIST -- PRESERVE-ONLY).
   *
   * Keyed by the plain u64 SEID; @p bar_id is used for logging only.
   *
   * PRESERVE-ONLY, and deliberately so: Setup() re-runs on every Session
   * Establishment/Modification that carries a BAR, and the XDP datapath
   * itself creates the entry (also with BPF_NOEXIST) on its missing-state
   * path. BPF_NOEXIST is what keeps an in-flight buffering state -- the
   * committed notify_epoch_ns, the buffered packet count -- alive across a
   * Create/Update BAR that happens while the UE is still idle. -EEXIST is
   * therefore the EXPECTED outcome, not an error.
   *
   * @warning This is NOT a reset. It can never clear a latched
   *          notification_sent / notify_epoch_ns. Use ResetBarState() for
   *          that -- see the contract there.
   *
   * @param seid    PFCP session identifier.
   * @param bar_id  BAR identifier.
   */
  void InitBarStateMap(uint64_t seid, uint32_t bar_id);

  /**
   * @brief Clear the one-shot DDN latch for a session (OVERWRITE, BPF_EXIST).
   *
   * Writes an all-zero `struct bar_state` over the existing entry, which
   * releases notify_epoch_ns back to NOTIFY_FREE, clears the derived
   * notification_sent mirror and zeroes buffered_pkt_count. This is the
   * counterpart of InitBarStateMap() and the ONLY supported way to re-arm a
   * session for a new idle -> paging cycle:
   *
   *   InitBarStateMap()  BPF_NOEXIST  create-if-absent, never overwrite
   *                                   (used by Create/Update BAR setup)
   *   ResetBarState()    BPF_EXIST    overwrite-if-present, never create
   *                                   (used when the FAR LEAVES buffering,
   *                                    on teardown, and by the UPF-T4
   *                                    consumer's pre-enqueue re-arm)
   *
   * @par Stale-SEID contract (UPF-T4 / plan P1-1)
   * BPF_EXIST -- not BPF_ANY -- is the guard: this call MUST NEVER create an
   * entry. The UPF-T4 DDN consumer re-arms the latch before re-enqueuing a
   * report, and by then the UP-SEID may already be torn down; a BPF_ANY
   * zero-write would resurrect a dead entry and leak a map slot that nothing
   * ever deletes again. An unknown SEID is reported as "nothing to reset"
   * (-ENOENT -> false), which is also the correct answer semantically: no
   * entry means no latch. Callers must only invoke this for a session they
   * believe is still present; a stale UP-SEID must be dropped and counted,
   * never re-armed.
   *
   * @note Never throws (TryUpdate, not Update). A throwing reset on the
   *       Session Modification path would abort the modification itself.
   * @note Races the XDP datapath, which creates the entry with BPF_NOEXIST on
   *       its missing-state path (UPF-T5). Both outcomes are benign: the
   *       entry exists and is zeroed, or it does not exist yet and there is
   *       nothing latched to clear.
   *
   * @param seid  PFCP session identifier (plain u64 key, as used by the XDP
   *              reader). bar_state_map holds one entry per session, so no
   *              BAR ID is needed.
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
};

#endif /* BAR_APPLY_USER_H_ */
