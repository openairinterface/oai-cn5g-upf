/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef MAR_APPLY_USER_H_
#define MAR_APPLY_USER_H_

#include <ProgramLifeCycle.hpp>
#include <linux/bpf.h>
#include <cstdint>
#include <memory>
#include <vector>
#include <xdp_mar_apply_skel.h>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "BPFProgram.h"
#include "upf_network_config.h"
#include <pfcp_mar.h>
#include <pfcp_session.hpp>

class BPFMaps;
class BPFMap;

using MarProgramLifeCycle = ProgramLifeCycle<xdp_mar_apply_kern_c>;

/**
 * @struct mar_map_key
 * @brief Compound BPF map key: {seid, mar_id}.
 */
struct mar_map_key {
  uint64_t seid;
  uint32_t mar_id;
  uint32_t _pad;
} __attribute__((packed));

/**
 * @class MARProgram
 * @brief Manages the xdp_mar_apply XDP program lifecycle.
 *
 * Follows the same constructor/Setup/TearDown/InitializeMaps pattern as
 * SessionLookupIPProgram. Instantiated by UPF_XDPProgram only when
 * flags.enable_mar is set.
 *
 * Lifecycle (orchestrated by UPF_XDPProgram):
 *   1. Constructor  -- creates lifecycle_, does NOT open skeleton.
 *   2. UPF_XDPProgram calls GetLifeCycle()->open() before ShareMaps().
 *   3. UPF_XDPProgram::ShareMaps(primary, this) -- reuse_fd for shared maps.
 *   4. Setup()      -- InitializeMaps() + load() (no attach, no link).
 *   5. TearDown()   -- lifecycle_->tearDown().
 */
class MARProgram : public BPFProgram {
 public:
  /** @brief Constructor -- creates lifecycle_, does NOT open skeleton. */
  MARProgram();

  /** @brief Destructor. */
  virtual ~MARProgram() = default;

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
   * @note Distinct from TearDown(seid, mars) which removes session map entries.
   */
  void TearDown();

  /**
   * @brief Returns the lifecycle for external orchestration.
   *
   * UPF_XDPProgram uses this to call open() before ShareMaps().
   */
  std::shared_ptr<MarProgramLifeCycle> GetLifeCycle() const {
    return lifecycle_;
  }

  /** @brief Returns the underlying bpf_object for map sharing. */
  struct bpf_object* GetBpfObject() const;

  /** @brief Returns the raw bpf_object_skeleton pointer. */
  struct bpf_object_skeleton* GetSkeleton() const;

  /**
   * @brief Returns the xdp_program* for insertion into tail_call_progs_map.
   *
   * Called by UPF_XDPProgram::InsertProgramSlot(PROG_MAR_APPLY, ...).
   */
  struct bpf_program* GetXdpProgram() const;

  /** @brief Returns the container of all maps in this skeleton. */
  std::shared_ptr<BPFMaps> GetMaps() const;

  /** @name Direct map accessors (mar_maps.h) */
  ///@{
  std::shared_ptr<BPFMap> GetMarConfigMap() const;
  std::shared_ptr<BPFMap> GetMarAccessStateMap() const;
  ///@}

  /** @brief Returns the number of maps in this skeleton. */
  size_t GetMapCount() const;

  // ==========================================================================
  // Session lifecycle (called by SessionProgramManager)
  // ==========================================================================

  /**
   * @brief Configure all MARs for a new session.
   * @param seid  PFCP session identifier.
   * @param mars  MAR IEs from PFCP Session Establishment Request.
   */
  void Setup(
      uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_mar>>& mars);

  /**
   * @brief Update a single MAR for an existing session.
   * @param seid  PFCP session identifier.
   * @param mar   Updated MAR IE from PFCP Session Modification Request.
   */
  void Update(uint64_t seid, const std::shared_ptr<pfcp::pfcp_mar>& mar);

  /**
   * @brief Remove a single MAR from all maps.
   * @param seid    PFCP session identifier.
   * @param mar_id  MAR identifier to remove.
   */
  void Remove(uint64_t seid, uint32_t mar_id);

  /**
   * @brief Tear down all MARs for a session on deletion.
   * @param seid  PFCP session identifier.
   * @param mars  MARs to remove.
   */
  void TearDown(
      uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_mar>>& mars);

  /**
   * @brief Populate mar_config_map for a single MAR.
   * @param seid   PFCP session identifier.
   * @param ie     MAR IE to convert and write.
   * @param flags  BPF_ANY / BPF_NOEXIST / BPF_EXIST.
   */
  void PopulateMarRulesMap(
      uint64_t seid, const std::shared_ptr<pfcp::pfcp_mar>& ie,
      uint64_t flags = BPF_ANY);

  /**
   * @brief Initialise mar_access_state_map entry (BPF_NOEXIST).
   * @param seid    PFCP session identifier.
   * @param mar_id  MAR identifier.
   */
  void InitMarAccessStateMap(uint64_t seid, uint32_t mar_id);

 private:
  /**
   * @brief Configure max_entries for all runtime-sized maps.
   *
   * Uses ConfigureMapMaxEntries(skel->maps.field, "name", size).
   * Called inside the open_fn lambda before the skeleton is returned.
   *
   * @param skel Opened (not yet loaded) skeleton.
   */
  void ConfigureMaps(struct xdp_mar_apply_kern_c* skel);

  /**
   * @brief Wrap skeleton map FDs in BPFMap objects after open.
   */
  void InitializeMaps();

  /** @brief Build a mar_map_key from SEID and MAR_ID (pad zeroed). */
  static mar_map_key MakeKey(uint64_t seid, uint32_t mar_id);

  /** @brief Translate PFCP MAR IE into BPF pfcp_mar struct. */
  static void ConvertMar(const pfcp::pfcp_mar& ie, struct pfcp_mar& bpf_mar);

  //----------------------------------------------------------------------------
  // Skeleton and lifecycle
  //----------------------------------------------------------------------------
  xdp_mar_apply_kern_c* skeleton_ = nullptr;
  std::shared_ptr<MarProgramLifeCycle> lifecycle_;

  //----------------------------------------------------------------------------
  // Maps (mar_maps.h)
  //----------------------------------------------------------------------------
  std::shared_ptr<BPFMaps> maps_;
  std::shared_ptr<BPFMap> mar_config_map_;
  std::shared_ptr<BPFMap> mar_access_state_map_;
};

#endif /* MAR_APPLY_USER_H_ */