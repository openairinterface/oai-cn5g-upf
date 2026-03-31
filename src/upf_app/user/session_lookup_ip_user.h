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
 * Changes:     Rewritten to follow n3_entry_user.h pattern exactly.
 *              - ConfigureMaps() separated and uses ConfigureMapMaxEntries
 *                (skel->maps.xxx) -- consistent with all other program classes.
 *              - Constructor no longer opens the skeleton (lazy, like entry
 *                programs). Open happens in Setup().
 *              - All 9 map members stored as class fields (not re-created on
 *                each getter call).
 *              - GetLifeCycle() added -- resolves TODO 2 from n3_entry_user.cpp:
 *                UPF_XDPProgram uses it to orchestrate open/load/share steps
 *                independently of Setup().
 *              - GetSkeleton() added for BPFMaps construction by orchestrator.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 -- PFCP Protocol (PDR/FAR/URR/BAR/MAR)
 *              3GPP TS 23.501          -- 5G System Architecture
 */
// clang-format on

/**
 * @file  session_lookup_ip_user.h
 * @brief User-space lifecycle manager for the xdp_session_lookup_ip XDP
 * program.
 *
 * Responsibilities:
 *   - Open the xdp_session_lookup_ip_kern_c skeleton and configure its maps.
 *   - Load the program (no attach/link -- stage program, reached via tail
 * call).
 *   - Expose all owned maps for use by the orchestrator UPF_XDPProgram.
 *
 * Maps owned (from xdp_session_lookup_ip_kern.c includes):
 *   pipeline_maps.h:
 *     - session_by_ue_ip_map      (runtime: MAX_PDU_SESSIONS)
 *     - pdrs_per_session_map      (runtime: MAX_PDU_SESSIONS)
 *     - session_qos_enabled_map   (runtime: MAX_PDU_SESSIONS)
 *     - rules_match_pdr_map       (runtime: MAX_PDU_SESSIONS x MAX_PDRS)
 *     - m_framed_route_mapping    (runtime: MAX_PDU_SESSIONS)
 *     - framed_routing_flag       (fixed: 1)
 *     - feature_dispatch_map      (fixed: tail_call array)
 *   tail_call_dispatcher.h (shared with entry programs via reuse_fd):
 *     - tail_call_progs_map       (fixed: 16)
 *     - packet_context_map        (fixed: 1)
 *     - session_rules_enabled_map (shared from primary skeleton)
 *
 * Rodata: 7 fields (MAX_UPF_INTERFACES, MAX_UPF_REDIRECT_INTERFACES,
 *   MAX_PDU_SESSIONS, MAX_PDRS_PER_PDU_SESSION,
 *   MAX_SDF_FILTERS_PER_PDU_SESSION, MAX_ARP_ENTRIES, MAX_QOS_ENABLING).
 *
 * @note Stage program -- no interface attachment. Reached exclusively via
 *       tail call from xdp_n3_entry (IP uplink) or xdp_n6_entry (IP downlink).
 */

#ifndef SESSION_LOOKUP_IP_USER_H_
#define SESSION_LOOKUP_IP_USER_H_

#include <ProgramLifeCycle.hpp>
#include <linux/bpf.h>
#include <memory>
#include <string>
#include <xdp_session_lookup_ip_skel.h>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "BPFProgram.h"
#include "upf_network_config.h"

class BPFMaps;
class BPFMap;

using SessionLookupIPLifeCycle = ProgramLifeCycle<xdp_session_lookup_ip_kern_c>;

/**
 * @class SessionLookupIPProgram
 * @brief Manages the xdp_session_lookup_ip XDP program lifecycle.
 *
 * Follows the same constructor/Setup/TearDown/InitializeMaps pattern as
 * N3EntryProgram. This is a STAGE program: it is loaded but never attached
 * or linked to an interface. It is invoked via tail call from the entry
 * programs on the IP PDU session data path.
 *
 * Lifecycle (orchestrated by UPF_XDPProgram):
 *   1. Constructor  -- creates lifecycle_, does NOT open skeleton.
 *   2. UPF_XDPProgram calls GetLifeCycle()->open() to get the bpf_object
 *      before ShareMaps().
 *   3. UPF_XDPProgram::ShareMaps(primary, this) -- reuse_fd for shared
 *      tail_call maps. Primary = n3_ (IP PDU) or n3_eth_ (ETH PDU).
 *   4. Setup()      -- InitializeMaps() + load() (no attach, no link).
 *   5. TearDown()   -- lifecycle_->tearDown().
 */
class SessionLookupIPProgram : public BPFProgram {
 public:
  /** @brief Constructor -- creates lifecycle_, does NOT open skeleton. */
  SessionLookupIPProgram();

  /** @brief Destructor. */
  virtual ~SessionLookupIPProgram();

  /**
   * @brief Initialize maps and load the XDP program into the kernel.
   *
   * Order: lifecycle_->open() (idempotent) → InitializeMaps() → load().
   * Must be called AFTER UPF_XDPProgram::ShareMaps() has reused the
   * tail_call map FDs from the primary (n3_entry) skeleton.
   * No attach() or link() -- stage programs are reached via tail call only.
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
   * UPF_XDPProgram uses this to:
   *   - Call open() before ShareMaps() (GetBpfObject() requires open).
   *   - Implement IsNativeXdp() / GetXdpModeString() without entry programs
   *     needing these methods directly (resolves TODO 2 from
   * n3_entry_user.cpp).
   */
  std::shared_ptr<SessionLookupIPLifeCycle> GetLifeCycle() const {
    return lifecycle_;
  }

  /** @brief Returns the underlying bpf_object for map sharing. */
  struct bpf_object* GetBpfObject() const;

  /**
   * @brief Returns the raw bpf_object_skeleton pointer.
   *
   * Used by BPFMaps construction:
   *   maps_ = std::make_shared<BPFMaps>(sl_ip_->GetSkeleton());
   */
  struct bpf_object_skeleton* GetSkeleton() const;

  /**
   * @brief Returns the xdp_program* for insertion into tail_call_progs_map.
   *
   * Called by UPF_XDPProgram::InsertProgramSlot(PROG_SESSION_LOOKUP_IP, ...).
   */
  struct bpf_program* GetXdpProgram() const;

  /** @brief Returns the container of all maps in this skeleton. */
  std::shared_ptr<BPFMaps> GetMaps() const;

  /** @name Direct map accessors (pipeline_maps.h) */
  ///@{
  std::shared_ptr<BPFMap> GetSessionByUeIpMap() const;
  std::shared_ptr<BPFMap> GetSessionPdrsMap() const;
  std::shared_ptr<BPFMap> GetSessionQosEnabledMap() const;
  std::shared_ptr<BPFMap> GetRulesMatchMap() const;
  std::shared_ptr<BPFMap> GetFramedRouteMappingMap() const;
  std::shared_ptr<BPFMap> GetFramedRoutingFlagMap() const;
  std::shared_ptr<BPFMap> GetFeatureDispatchMap() const;
  ///@}

  /** @name Direct map accessors (tail_call_dispatcher.h -- shared) */
  ///@{
  std::shared_ptr<BPFMap> GetTailCallProgsMap() const;
  std::shared_ptr<BPFMap> GetPacketContextMap() const;
  std::shared_ptr<BPFMap> GetSessionRulesEnabledMap() const;
  ///@}

  /** @brief Returns the number of maps in this skeleton. */
  size_t GetMapCount() const;

 private:
  /**
   * @brief Configure max_entries for all runtime-sized maps.
   *
   * Uses ConfigureMapMaxEntries(skel->maps.field, "name", size) -- the same
   * pattern as the original upf_xdp_user.cpp and all other program classes.
   * Called inside the open_fn lambda before the skeleton is returned.
   *
   * @param skel Opened (not yet loaded) skeleton.
   */
  void ConfigureMaps(struct xdp_session_lookup_ip_kern_c* skel);

  /**
   * @brief Wrap skeleton map FDs in BPFMap objects after open.
   *
   * Called from Setup() so that map pointers are valid before the program
   * is loaded into the kernel.
   */
  void InitializeMaps();

  //----------------------------------------------------------------------------
  // Skeleton and lifecycle
  //----------------------------------------------------------------------------
  xdp_session_lookup_ip_kern_c* skeleton_ = nullptr;
  std::shared_ptr<SessionLookupIPLifeCycle> lifecycle_;

  //----------------------------------------------------------------------------
  // Maps -- pipeline_maps.h
  //----------------------------------------------------------------------------
  std::shared_ptr<BPFMaps> maps_;
  std::shared_ptr<BPFMap> session_by_ue_ip_map_;
  std::shared_ptr<BPFMap> pdrs_per_session_map_;
  std::shared_ptr<BPFMap> session_qos_enabled_map_;
  std::shared_ptr<BPFMap> rules_match_pdr_map_;
  std::shared_ptr<BPFMap> framed_route_mapping_map_;
  std::shared_ptr<BPFMap> framed_routing_flag_map_;
  std::shared_ptr<BPFMap> feature_dispatch_map_;
  //----------------------------------------------------------------------------
  // Maps -- tail_call_dispatcher.h
  // Shared from the primary entry program via bpf_map__reuse_fd.
  // Primary is n3_ (IP PDU) or n3_eth_ (ETH PDU) -- both include
  // tail_call_dispatcher.h so the same maps exist in either case.
  //----------------------------------------------------------------------------
  std::shared_ptr<BPFMap> tail_call_progs_map_;
  std::shared_ptr<BPFMap> packet_ctx_map_;
  std::shared_ptr<BPFMap> session_rules_enabled_map_;
};

#endif /* SESSION_LOOKUP_IP_USER_H_ */
