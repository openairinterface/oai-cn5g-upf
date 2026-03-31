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
 * Changes:     Rewritten to follow n3_entry_user.h / session_lookup_ip_user.h
 *              pattern exactly.
 *              xdp_pdr_match_kern.c includes:
 *                sdf_maps.h     -> sdf_filters_map        (runtime sized, owned)
 *                pipeline_maps.h -> pdrs_per_session_map  (shared via reuse_fd)
 *                                   rules_match_pdr_map   (shared via reuse_fd)
 *              rodata: MAX_PDU_SESSIONS, MAX_PDRS_PER_PDU_SESSION,
 *                      MAX_SDF_FILTERS_PER_PDU_SESSION.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 §7.5.2.3 Create PDR
 */
// clang-format on

/**
 * @file  pdr_match_user.h
 * @brief User-space lifecycle manager for the xdp_pdr_match XDP program.
 *
 * Responsibilities:
 *   - Open the xdp_pdr_match_kern_c skeleton and configure its maps.
 *   - Load the program (no attach/link -- stage program, reached via tail
 *     call).
 *   - Expose owned maps and provide session-level PDR map management.
 *
 * Maps owned (from xdp_pdr_match_kern.c includes):
 *   sdf_maps.h:
 *     - sdf_filters_map          (runtime: MAX_PDU_SESSIONS x
 *                                          MAX_SDF_FILTERS_PER_PDU_SESSION)
 *   pipeline_maps.h (shared from primary via reuse_fd):
 *     - pdrs_per_session_map     (accessed, not owned)
 *     - rules_match_pdr_map      (accessed, not owned)
 *
 * Rodata: MAX_PDU_SESSIONS, MAX_PDRS_PER_PDU_SESSION,
 *         MAX_SDF_FILTERS_PER_PDU_SESSION.
 *
 * @note Stage program -- no interface attachment. Reached exclusively via
 *       tail call from the session lookup programs.
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