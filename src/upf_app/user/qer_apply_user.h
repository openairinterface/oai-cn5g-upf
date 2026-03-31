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
 * Changes:     New file. Follows n3_entry_user.h / session_lookup_ip_user.h
 *              pattern exactly (same as urr_apply_user.h / bar_apply_user.h).
 *              xdp_qer_apply_kern.c includes:
 *                pipeline_maps.h       -> rules_match_pdr_map (shared via reuse_fd)
 *                interfaces_maps.h     -> (shared via reuse_fd)
 *                tail_call_dispatcher.h -> (shared via reuse_fd)
 *                stats_maps.h          -> (shared via reuse_fd)
 *              Owns NO maps -- all maps are shared from the primary entry
 *              program via bpf_map__reuse_fd (gate check is stateless).
 *              rodata: 7 fields (pipeline_maps.h declares all 7).
 *              DISTINCT from QERProgram (qer_tc_user.h) which manages the
 *              TC-BPF programs for per-session HTB rate shaping.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 §8.2.40 QER ID
 *              §8.2.41 Gate Status (UL/DL)
 *              §8.2.42 MBR   §8.2.43 GBR
 */
// clang-format on

/**
 * @file  qer_apply_user.h
 * @brief User-space lifecycle manager for the xdp_qer_apply XDP program.
 *
 * Responsibilities:
 *   - Open the xdp_qer_apply_kern_c skeleton and set its rodata constants.
 *   - Load the program (no attach/link -- stage program, reached via tail
 *     call at slot PROG_QER_APPLY).
 *   - Perform gate-check (UL/DL gate OPEN/CLOSED) and write QoS metadata
 *     (SEID + QFI) to XDP meta for the TC layer on downlink packets.
 *
 * Maps owned (from xdp_qer_apply_kern.c): NONE.
 *   All maps (rules_match_pdr_map, tail_call_progs_map, packet_context_map,
 *   session_rules_enabled_map, mc_stats_map) are declared in pipeline_maps.h
 *   and shared from the primary entry program via bpf_map__reuse_fd.
 *
 * Rodata: 7 fields (pipeline_maps.h):
 *   MAX_UPF_INTERFACES, MAX_UPF_REDIRECT_INTERFACES, MAX_PDU_SESSIONS,
 *   MAX_PDRS_PER_PDU_SESSION, MAX_SDF_FILTERS_PER_PDU_SESSION,
 *   MAX_ARP_ENTRIES, MAX_QOS_ENABLING.
 *
 * @note Stage program -- no interface attachment.
 * @note Instantiated by UPF_XDPProgram only when flags.enable_qer is set.
 * @note Per-session QER lifecycle (HTB class setup, TC filter attachment)
 *       is managed by QERProgram (qer_tc_user.h), not this class.
 */

#ifndef QER_APPLY_USER_H_
#define QER_APPLY_USER_H_

#include <ProgramLifeCycle.hpp>
#include <linux/bpf.h>
#include <memory>
#include <xdp_qer_apply_skel.h>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "BPFProgram.h"
#include "upf_network_config.h"

class BPFMaps;
class BPFMap;

using QerProgramLifeCycle = ProgramLifeCycle<xdp_qer_apply_kern_c>;

/**
 * @class QERProgram
 * @brief Manages the xdp_qer_apply XDP program lifecycle.
 *
 * Follows the same constructor/Setup/TearDown/InitializeMaps pattern as
 * URRProgram, BARProgram, and MARProgram. Instantiated by UPF_XDPProgram
 * only when flags.enable_qer is set.
 *
 * Lifecycle (orchestrated by UPF_XDPProgram):
 *   1. Constructor  -- creates lifecycle_, does NOT open skeleton.
 *   2. UPF_XDPProgram calls GetLifeCycle()->open() before ShareMaps().
 *   3. UPF_XDPProgram::ShareMaps(primary, this) -- reuse_fd for all maps.
 *   4. Setup()      -- InitializeMaps() + load() (no attach, no link).
 *   5. TearDown()   -- lifecycle_->tearDown().
 */
class QERProgram : public BPFProgram {
 public:
  /** @brief Constructor -- creates lifecycle_, does NOT open skeleton. */
  QERProgram();

  /** @brief Destructor. */
  virtual ~QERProgram() = default;

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
  std::shared_ptr<QerProgramLifeCycle> GetLifeCycle() const {
    return lifecycle_;
  }

  /** @brief Returns the underlying bpf_object for map sharing. */
  struct bpf_object* GetBpfObject() const;

  /** @brief Returns the raw bpf_object_skeleton pointer. */
  struct bpf_object_skeleton* GetSkeleton() const;

  /**
   * @brief Returns the xdp_program* for insertion into tail_call_progs_map.
   *
   * Called by UPF_XDPProgram::InsertProgramSlot(PROG_QER_APPLY, ...).
   */
  struct bpf_program* GetXdpProgram() const;

  /** @brief Returns the container of all maps in this skeleton. */
  std::shared_ptr<BPFMaps> GetMaps() const;

  /** @brief Returns the number of maps in this skeleton. */
  size_t GetMapCount() const;

 private:
  /**
   * @brief Set rodata constants before skeleton load.
   *
   * xdp_qer_apply_kern.c includes pipeline_maps.h which declares 7 rodata
   * fields. No ConfigureMapMaxEntries() calls are needed because this
   * program owns no maps -- all maps are shared from the primary via
   * bpf_map__reuse_fd before Setup() is called.
   *
   * @param skel Opened (not yet loaded) skeleton.
   */
  void ConfigureMaps(struct xdp_qer_apply_kern_c* skel);

  /**
   * @brief Wrap skeleton map FDs in BPFMaps after open.
   *
   * All maps are shared from the primary entry program via reuse_fd.
   * maps_ is created here solely to support GetMapCount().
   */
  void InitializeMaps();

  //----------------------------------------------------------------------------
  // Skeleton and lifecycle
  //----------------------------------------------------------------------------
  xdp_qer_apply_kern_c* skeleton_ = nullptr;
  std::shared_ptr<QerProgramLifeCycle> lifecycle_;

  //----------------------------------------------------------------------------
  // Maps -- NONE owned by this program.
  // maps_ wraps the skeleton for GetMapCount() only.
  //----------------------------------------------------------------------------
  std::shared_ptr<BPFMaps> maps_;
};

#endif /* QER_APPLY_USER_H_ */