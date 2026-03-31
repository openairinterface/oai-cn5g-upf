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
 *              xdp_mar_apply_kern.c includes:
 *                mar_maps.h -> mar_config_map       (runtime, owned)
 *                              mar_access_state_map (runtime, owned)
 *              rodata: MAX_PDU_SESSIONS.
 *              All session lifecycle methods preserved unchanged.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 §8.2.123 MAR ID
 *              3GPP TS 23.501 §5.32 -- ATSSS
 */
// clang-format on

/**
 * @file  mar_apply_user.h
 * @brief User-space lifecycle manager for the xdp_mar_apply XDP program.
 *
 * Responsibilities:
 *   - Open the xdp_mar_apply_kern_c skeleton and configure its maps.
 *   - Load the program (no attach/link -- stage program, reached via tail
 *     call).
 *   - Manage per-session MAR configuration maps on behalf of
 *     SessionProgramManager.
 *
 * Maps owned (from xdp_mar_apply_kern.c includes, mar_maps.h):
 *   - mar_config_map       (runtime: MAX_PDU_SESSIONS)
 *   - mar_access_state_map (runtime: MAX_PDU_SESSIONS)
 *
 * Rodata: MAX_PDU_SESSIONS.
 *
 * @note Stage program -- no interface attachment.
 * @note Instantiated by UPF_XDPProgram only when flags.enable_mar is set.
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