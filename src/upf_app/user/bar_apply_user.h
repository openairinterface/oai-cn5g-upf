/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef BAR_APPLY_USER_H_
#define BAR_APPLY_USER_H_

#include <ProgramLifeCycle.hpp>
#include <linux/bpf.h>
#include <cstdint>
#include <memory>
#include <vector>
#include <xdp_bar_apply_skel.h>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "BPFProgram.h"
#include "upf_network_config.h"
#include <pfcp_bar.h>
#include <pfcp_session.hpp>

class BPFMaps;
class BPFMap;

using BarProgramLifeCycle = ProgramLifeCycle<xdp_bar_apply_kern_c>;

/**
 * @struct bar_map_key
 * @brief Compound BPF map key: {seid, bar_id}.
 */
struct bar_map_key {
  uint64_t seid;
  uint32_t bar_id;
  uint32_t _pad;
} __attribute__((packed));

/**
 * @struct bar_state_t
 * @brief Per-BAR runtime buffering state maintained atomically by data plane.
 *
 * Initialised with BPF_NOEXIST on session creation so that existing state
 * is preserved across session modifications.
 */
struct bar_state_t {
  uint64_t last_ddn_ns;
  uint32_t buffered_pkt_count;
  uint8_t notification_sent;
  uint8_t _pad[3];
};

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
   * @brief Configure all BARs for a new session.
   *
   * Populates bar_config_map and initialises bar_state_map (BPF_NOEXIST)
   * for each BAR in the list.
   *
   * @param seid  PFCP session identifier.
   * @param bars  BAR IEs from PFCP Session Establishment Request.
   */
  void Setup(
      uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_bar>>& bars);

  /**
   * @brief Update a single BAR for an existing session.
   *
   * Overwrites the config entry; bar_state_map is NOT touched so that DDN
   * suppression state and buffered packet count are preserved.
   *
   * @param seid  PFCP session identifier.
   * @param bar   Updated BAR IE from PFCP Session Modification Request.
   */
  void Update(uint64_t seid, const std::shared_ptr<pfcp::pfcp_bar>& bar);

  /**
   * @brief Remove a single BAR from all maps.
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
   * @brief Populate bar_config_map for a single BAR.
   * @param seid   PFCP session identifier.
   * @param bar    BAR IE to convert and write.
   * @param flags  BPF_ANY / BPF_NOEXIST / BPF_EXIST.
   */
  void PopulateBarConfigMap(
      uint64_t seid, const std::shared_ptr<pfcp::pfcp_bar>& bar,
      uint64_t flags = BPF_ANY);

  /**
   * @brief Initialise bar_state_map entry (BPF_NOEXIST -- preserves state).
   * @param seid    PFCP session identifier.
   * @param bar_id  BAR identifier.
   */
  void InitBarStateMap(uint64_t seid, uint32_t bar_id);

  /**
   * @brief Read current buffering state for a BAR.
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

  /** @brief Build a bar_map_key from SEID and BAR_ID (pad zeroed). */
  static bar_map_key MakeKey(uint64_t seid, uint32_t bar_id);

  /** @brief Translate PFCP BAR IE into BPF pfcp_bar struct. */
  static void ConvertBar(const pfcp::pfcp_bar& ie, struct pfcp_bar& bpf_bar);

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