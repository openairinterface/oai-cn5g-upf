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
 * Changes:     New file. Dedicated user-space class for xdp_n3_entry_kern_c.
 *              xdp_n3_entry_kern.c includes only stats_maps.h (mc_stats_map,
 *              fixed size) and tail_call_dispatcher.h (tail_call_progs_map,
 *              packet_context_map, session_rules_enabled_map -- all fixed or
 *              sized by the owning program).
 *              No runtime map configuration needed in ConfigureMaps().
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 -- PFCP Protocol
 *              3GPP TS 23.501          -- 5G System Architecture (N3 interface)
 */
// clang-format on

/**
 * @file  n3_entry_user.h
 * @brief User-space lifecycle manager for the xdp_n3_entry XDP program.
 *
 * Responsibilities:
 *   - Open the xdp_n3_entry_kern_c skeleton and configure its maps.
 *   - Load, attach, and link the program to the GTP (N3) interface.
 *   - Expose the maps it owns for use by the orchestrator UPF_XDPProgram.
 *
 * Maps owned (from xdp_n3_entry_kern.c includes):
 *   - tail_call_progs_map      (tail_call_dispatcher.h, fixed size)
 *   - packet_context_map       (tail_call_dispatcher.h, fixed size)
 *   - session_rules_enabled_map(tail_call_dispatcher.h, fixed size)
 *   - mc_stats_map             (stats_maps.h,           fixed size)
 *
 * @note This class does NOT own pipeline maps, interface maps, or ARP maps.
 *       Those belong to the programs whose kernel files include the
 *       corresponding map headers.
 */

#ifndef N3_ENTRY_USER_H_
#define N3_ENTRY_USER_H_

#include <ProgramLifeCycle.hpp>
#include <linux/bpf.h>
#include <memory>
#include <string>
#include <xdp_n3_entry_skel.h>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "BPFProgram.h"
#include "interfaces_types.h"
#include "upf_network_config.h"

class BPFMaps;
class BPFMap;

using N3EntryLifeCycle = ProgramLifeCycle<xdp_n3_entry_kern_c>;

/**
 * @class N3EntryProgram
 * @brief Manages the xdp_n3_entry XDP program lifecycle.
 *
 * Follows the same constructor/Setup/TearDown/InitializeMaps pattern as
 * the original monolithic upf_xdp_user. Instantiated by UPF_XDPProgram
 * when IP PDU sessions are configured (pdu_type != Ethernet).
 * Acts as the PRIMARY program for the IP PDU path: loaded first so
 * its map FDs are shared to all other programs via bpf_map__reuse_fd.
 * Not instantiated in ETH PDU mode (n3_eth_ is primary instead).
 *
 * Lifecycle (called from UPF_XDPProgram):
 *   1. Constructor  -- open skeleton + ConfigureMaps()
 *   2. Setup()      -- InitializeMaps() + load() + attach() + link()
 *   3. TearDown()   -- lifecycle_->tearDown()
 */

class N3EntryProgram : public BPFProgram {
 public:
  /**
   * @brief Constructor -- opens skeleton and configures maps.
   * @param gtp_interface Name of the N3 (GTP-U) network interface.
   */
  explicit N3EntryProgram(const std::string& gtp_interface);

  /** @brief Destructor. */
  virtual ~N3EntryProgram();

  /**
   * @brief Load, attach, and link the XDP program to the GTP interface.
   *
   * Order: InitializeMaps() → load() → attach() → link().
   * Must be called after all map sharing (bpf_map__reuse_fd) is done
   * by the orchestrator.
   */
  void Setup();

  /**
   * @brief Detach and unload the XDP program.
   *
   * Delegates to lifecycle_->tearDown().
   */
  void TearDown();

  /** @brief Returns the container of all maps in this skeleton. */
  std::shared_ptr<BPFMaps> GetMaps();

  /**
   * @brief Get a map by name.
   *
   * Supports the 4 maps owned by this program. Returns nullptr if
   * the name is not recognised.
   *
   * @param map_name BPF map name string.
   * @return Shared pointer to the map, or nullptr.
   */
  std::shared_ptr<BPFMap> GetMapByName(const std::string& map_name);

  /** @name Direct map accessors */
  ///@{
  std::shared_ptr<BPFMap> GetTailCallProgsMap() const;
  std::shared_ptr<BPFMap> GetPacketContextMap() const;
  std::shared_ptr<BPFMap> GetSessionRulesEnabledMap() const;
  std::shared_ptr<BPFMap> GetMcStatsMap() const;
  ///@}

  /**
   * @brief Returns the number of maps in this skeleton.
   * @note  See TODO in .cpp regarding ownership of this counter.
   */
  size_t GetMapCount() const;

  /**
   * @brief Returns the lifecycle for external orchestration by UPF_XDPProgram.
   *
   * Used to call open()/load()/attach()/link() independently, and to
   * implement IsNativeXdp() / GetXdpModeString() in UPF_XDPProgram
   * without these methods living in individual entry program classes.
   * Resolves TODO 2 from n3_entry_user.cpp.
   */
  std::shared_ptr<N3EntryLifeCycle> GetLifeCycle() const { return lifecycle_; }

  /** @brief Returns the underlying bpf_object for map sharing. */
  struct bpf_object* GetBpfObject() const;

  /**
   * @brief Returns the raw bpf_object_skeleton pointer.
   *
   * Used by BPFMaps construction after load:
   *   maps_ = std::make_shared<BPFMaps>(n3_->GetSkeleton());
   */
  struct bpf_object_skeleton* GetSkeleton() const;

  /**
   * @brief Returns true if the interface runs in native XDP mode.
   * @note  See TODO in .cpp -- this may be relocated in a future refactor.
   */
  bool IsNativeXdp(const std::string& interface) const;

  /**
   * @brief Returns a human-readable XDP mode string ("Native" or "SKB").
   * @note  See TODO in .cpp -- this may be relocated in a future refactor.
   */
  std::string GetXdpModeString(const std::string& interface) const;

 private:
  /**
   * @brief Called inside open_fn to set max_entries on runtime-sized maps.
   *
   * For N3EntryProgram all maps are fixed size so this is currently a no-op.
   * Kept for structural consistency with other program classes.
   *
   * @param skel Opened (not yet loaded) skeleton.
   */
  void ConfigureMaps(struct xdp_n3_entry_kern_c* skel);

  /**
   * @brief Wrap skeleton map FDs in BPFMap objects after load.
   *
   * Called from Setup() after lifecycle_->open() so that map pointers
   * are valid before the program is loaded into the kernel.
   */
  void InitializeMaps();

  //----------------------------------------------------------------------------
  // Skeleton and lifecycle
  //----------------------------------------------------------------------------
  xdp_n3_entry_kern_c* skeleton_ = nullptr;
  std::shared_ptr<N3EntryLifeCycle> lifecycle_;

  //----------------------------------------------------------------------------
  // Interface
  //----------------------------------------------------------------------------
  std::string gtp_interface_;

  //----------------------------------------------------------------------------
  // Maps (tail_call_dispatcher.h + stats_maps.h)
  //----------------------------------------------------------------------------
  std::shared_ptr<BPFMaps> maps_;
  std::shared_ptr<BPFMap> tail_call_progs_map_;
  std::shared_ptr<BPFMap> packet_ctx_map_;
  std::shared_ptr<BPFMap> session_rules_enabled_map_;
  std::shared_ptr<BPFMap> mc_stats_map_;
};

#endif /* N3_ENTRY_USER_H_ */
