/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef PDR_MATCH_USER_H_
#define PDR_MATCH_USER_H_

#include <ProgramLifeCycle.hpp>
#include <linux/bpf.h>
#include <cstdint>
#include <memory>
#include <vector>
#include <xdp_pdr_match_skel.h>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "BPFProgram.h"
#include "upf_network_config.h"
#include <pfcp_pdr.hpp>
#include <pfcp_session.hpp>

class BPFMaps;
class BPFMap;

using PdrMatchProgramLifeCycle = ProgramLifeCycle<xdp_pdr_match_kern_c>;

/**
 * @struct pdr_rule_association
 * @brief Rule ID associations stored in rules_match_pdr_map per PDR.
 */
struct pdr_rule_association {
  uint32_t pdr_id;
  uint32_t far_id;
  uint32_t qer_id;
  uint32_t urr_id;
  uint32_t bar_id;
  uint32_t mar_id;
  uint32_t rules_enabled;
  uint32_t _pad;
};

/**
 * @struct pdr_rule_key
 * @brief Compound BPF map key: {seid, pdr_id}.
 */
struct pdr_rule_key {
  uint64_t seid;
  uint32_t pdr_id;
  uint32_t _pad;
} __attribute__((packed));

/**
 * @class PdrMatchProgram
 * @brief Manages the xdp_pdr_match XDP program lifecycle.
 *
 * Follows the same constructor/Setup/TearDown/InitializeMaps pattern as
 * SessionLookupIPProgram. Always instantiated by UPF_XDPProgram.
 *
 * Lifecycle (orchestrated by UPF_XDPProgram):
 *   1. Constructor  -- creates lifecycle_, does NOT open skeleton.
 *   2. UPF_XDPProgram calls GetLifeCycle()->open() before ShareMaps().
 *   3. UPF_XDPProgram::ShareMaps(primary, this) -- reuse_fd for shared maps.
 *   4. Setup()      -- InitializeMaps() + load() (no attach, no link).
 *   5. TearDown()   -- lifecycle_->tearDown().
 */
class PdrMatchProgram : public BPFProgram {
 public:
  /** @brief Constructor -- creates lifecycle_, does NOT open skeleton. */
  PdrMatchProgram();

  /** @brief Destructor. */
  virtual ~PdrMatchProgram() = default;

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
   */
  void TearDown();

  /**
   * @brief Returns the lifecycle for external orchestration.
   *
   * UPF_XDPProgram uses this to call open() before ShareMaps().
   */
  std::shared_ptr<PdrMatchProgramLifeCycle> GetLifeCycle() const {
    return lifecycle_;
  }

  /** @brief Returns the underlying bpf_object for map sharing. */
  struct bpf_object* GetBpfObject() const;

  /** @brief Returns the raw bpf_object_skeleton pointer. */
  struct bpf_object_skeleton* GetSkeleton() const;

  /**
   * @brief Returns the xdp_program* for insertion into tail_call_progs_map.
   *
   * Called by UPF_XDPProgram::InsertProgramSlot(PROG_PDR_MATCH, ...).
   */
  struct bpf_program* GetXdpProgram() const;

  /** @brief Returns the container of all maps in this skeleton. */
  std::shared_ptr<BPFMaps> GetMaps() const;

  /** @name Direct map accessors */
  ///@{
  /** @return Shared pointer to sdf_filters_map (owned). */
  std::shared_ptr<BPFMap> GetSdfFilterMap() const;
  /** @return Shared pointer to pdrs_per_session_map (shared via reuse_fd). */
  std::shared_ptr<BPFMap> GetSessionPdrsMap() const;
  /** @return Shared pointer to rules_match_pdr_map (shared via reuse_fd). */
  std::shared_ptr<BPFMap> GetRulesMatchMap() const;
  ///@}

  /** @brief Returns the number of maps in this skeleton. */
  size_t GetMapCount() const;

  // ==========================================================================
  // Session lifecycle (called by SessionProgramManager)
  // ==========================================================================

  /**
   * @brief Configure all PDR matching maps for a new or updated session.
   *
   * Writes rule associations and SDF filters for all uplink and downlink PDRs.
   * PDRs MUST already be sorted by precedence by the caller.
   *
   * @param seid           PFCP session identifier.
   * @param pdrs_ul        Uplink PDRs (sorted ascending by precedence).
   * @param pdrs_dl        Downlink PDRs (sorted ascending by precedence).
   * @param rules_enabled  Per-PDR rules_enabled bitmask (from ComputeFlags).
   */
  void PopulatePdrRulesMaps(
      uint64_t seid,
      const std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs_ul,
      const std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs_dl,
      uint32_t rules_enabled);

  /**
   * @brief Remove all PDR matching map entries for a session.
   *
   * @param seid  PFCP session identifier.
   * @param pdrs  All PDRs (uplink + downlink combined).
   */
  void RemovePdrRulesMaps(
      uint64_t seid, const std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs);

  /**
   * @brief Populate sdf_filters_map for a single PDR.
   *
   * @param seid  PFCP session identifier.
   * @param pdr   PDR containing the PDI with optional SDF filter IE.
   */
  void PopulateSdfFilterMap(
      uint64_t seid, const std::shared_ptr<pfcp::pfcp_pdr>& pdr);

  /**
   * @brief Populate rules_match_pdr_map for a single PDR.
   *
   * @param seid           PFCP session identifier.
   * @param pdr            PDR to translate.
   * @param rules_enabled  Rules bitmask for the tail-call skip-chain.
   */
  void PopulateRulesMatchPdrMap(
      uint64_t seid, const std::shared_ptr<pfcp::pfcp_pdr>& pdr,
      uint32_t rules_enabled);

 private:
  /**
   * @brief Configure max_entries for all runtime-sized maps.
   *
   * Uses ConfigureMapMaxEntries(skel->maps.field, "name", size).
   * Called inside the open_fn lambda before the skeleton is returned.
   *
   * @param skel Opened (not yet loaded) skeleton.
   */
  void ConfigureMaps(struct xdp_pdr_match_kern_c* skel);

  /**
   * @brief Wrap skeleton map FDs in BPFMap objects after open.
   *
   * Called from Setup() so that map pointers are valid before load.
   */
  void InitializeMaps();

  /** @brief Build a pdr_rule_key from SEID and PDR_ID (pad zeroed). */
  static pdr_rule_key MakePdrKey(uint64_t seid, uint32_t pdr_id);

  //----------------------------------------------------------------------------
  // Skeleton and lifecycle
  //----------------------------------------------------------------------------
  xdp_pdr_match_kern_c* skeleton_ = nullptr;
  std::shared_ptr<PdrMatchProgramLifeCycle> lifecycle_;

  //----------------------------------------------------------------------------
  // Maps
  //   sdf_filter_map_:   owned (sdf_maps.h)
  //   session_pdrs_map_, rules_match_map_: shared from primary via reuse_fd
  //   (pipeline_maps.h)
  //----------------------------------------------------------------------------
  std::shared_ptr<BPFMaps> maps_;
  std::shared_ptr<BPFMap> sdf_filter_map_;
  std::shared_ptr<BPFMap> session_pdrs_map_;
  std::shared_ptr<BPFMap> rules_match_map_;
};

#endif /* PDR_MATCH_USER_H_ */