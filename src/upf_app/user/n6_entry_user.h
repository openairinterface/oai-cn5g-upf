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
 * Changes:     New file. Dedicated user-space class for xdp_n6_entry_kern_c.
 *              xdp_n6_entry_kern.c includes:
 *                sdf_types.h            -> type definitions only, no maps
 *                tail_call_dispatcher.h -> tail_call_progs_map (fixed)
 *                                         packet_context_map   (fixed)
 *                                         session_rules_enabled_map (fixed/sized by owner)
 *                stats_maps.h           -> mc_stats_map (fixed)
 *              No runtime map configuration needed in ConfigureMaps().
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 -- PFCP Protocol
 *              3GPP TS 23.501          -- 5G System Architecture (N6 interface)
 */
// clang-format on

/**
 * @file  n6_entry_user.h
 * @brief User-space lifecycle manager for the xdp_n6_entry XDP program.
 *
 * Responsibilities:
 *   - Open the xdp_n6_entry_kern_c skeleton and configure its maps.
 *   - Load, attach, and link the program to the non-GTP (N6) interface.
 *   - Expose the maps it owns for use by the orchestrator UPF_XDPProgram.
 *
 * Maps owned (from xdp_n6_entry_kern.c includes):
 *   - tail_call_progs_map       (tail_call_dispatcher.h, fixed size)
 *   - packet_context_map        (tail_call_dispatcher.h, fixed size)
 *   - session_rules_enabled_map (tail_call_dispatcher.h, fixed/sized by owner)
 *   - mc_stats_map              (stats_maps.h,           fixed size)
 *
 * @note This class does NOT own pipeline maps, interface maps, or ARP maps.
 */

#ifndef N6_ENTRY_USER_H_
#define N6_ENTRY_USER_H_

#include <ProgramLifeCycle.hpp>
#include <linux/bpf.h>
#include <memory>
#include <string>
#include <xdp_n6_entry_skel.h>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "BPFProgram.h"
#include "upf_network_config.h"

class BPFMaps;
class BPFMap;

using N6EntryLifeCycle = ProgramLifeCycle<xdp_n6_entry_kern_c>;

/**
 * @class N6EntryProgram
 * @brief Manages the xdp_n6_entry XDP program lifecycle.
 *
 * Follows the same constructor/Setup/TearDown/InitializeMaps pattern as
 * N3EntryProgram. Instantiated by UPF_XDPProgram when IP PDU sessions are
 * configured (pdu_type != Ethernet).
 * Secondary entry program on the IP PDU path (n3_ is primary).
 * Not instantiated in ETH PDU mode.
 *
 * Lifecycle (called from UPF_XDPProgram):
 *   1. Constructor  -- open skeleton + ConfigureMaps()
 *   2. Setup()      -- InitializeMaps() + load() + attach() + link()
 *   3. TearDown()   -- lifecycle_->tearDown()
 */
class N6EntryProgram : public BPFProgram {
 public:
  /**
   * @brief Constructor -- opens skeleton and configures maps.
   * @param non_gtp_interface Name of the N6 network interface.
   */
  explicit N6EntryProgram(const std::string& non_gtp_interface);

  /** @brief Destructor. */
  virtual ~N6EntryProgram();

  /**
   * @brief Load, attach, and link the XDP program to the N6 interface.
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

  /** @brief Returns the number of maps in this skeleton. */
  size_t GetMapCount() const;

  /**
   * @brief Returns the lifecycle for external orchestration by UPF_XDPProgram.
   *
   * Used to call open()/load()/attach()/link() independently, and to
   * implement IsNativeXdp() / GetXdpModeString() in UPF_XDPProgram
   * without these methods living in individual entry program classes.
   * Resolves TODO 2 from n3_entry_user.cpp.
   */
  std::shared_ptr<N6EntryLifeCycle> GetLifeCycle() const { return lifecycle_; }

  /** @brief Returns the underlying bpf_object for map sharing. */
  struct bpf_object* GetBpfObject() const;

  /** @brief Returns the raw bpf_object_skeleton pointer. */
  struct bpf_object_skeleton* GetSkeleton() const;

  /**
   * @brief Returns true if the interface runs in native XDP mode.
   * @note See TODO in n3_entry_user.cpp -- to be relocated to UPF_XDPProgram.
   */
  bool IsNativeXdp(const std::string& interface) const;

  /**
   * @brief Returns a human-readable XDP mode string ("Native" or "SKB").
   * @note See TODO in n3_entry_user.cpp -- to be relocated to UPF_XDPProgram.
   */
  std::string GetXdpModeString(const std::string& interface) const;

 private:
  /**
   * @brief No-op for N6EntryProgram -- all maps are fixed size.
   * @param skel Opened (not yet loaded) skeleton.
   */
  void ConfigureMaps(struct xdp_n6_entry_kern_c* skel);

  /**
   * @brief Wrap skeleton map FDs in BPFMap objects after open.
   */
  void InitializeMaps();

  //----------------------------------------------------------------------------
  // Skeleton and lifecycle
  //----------------------------------------------------------------------------
  xdp_n6_entry_kern_c* skeleton_ = nullptr;
  std::shared_ptr<N6EntryLifeCycle> lifecycle_;

  //----------------------------------------------------------------------------
  // Interface
  //----------------------------------------------------------------------------
  std::string non_gtp_interface_;

  //----------------------------------------------------------------------------
  // Maps (tail_call_dispatcher.h + stats_maps.h)
  //----------------------------------------------------------------------------
  std::shared_ptr<BPFMaps> maps_;
  std::shared_ptr<BPFMap> tail_call_progs_map_;
  std::shared_ptr<BPFMap> packet_ctx_map_;
  std::shared_ptr<BPFMap> session_rules_enabled_map_;
  std::shared_ptr<BPFMap> mc_stats_map_;
};

#endif /* N6_ENTRY_USER_H_ */
