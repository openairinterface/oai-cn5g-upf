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
 * Changes:     New file. Dedicated user-space class for xdp_n6_eth_entry_kern_c.
 *              xdp_n6_eth_entry_kern.c includes:
 *                interfaces_maps.h -> upf_interface_map        (runtime sized)
 *                                     redirect_interfaces_map  (runtime sized)
 *                eth_pdu_maps.h    -> session_by_mac_map        (runtime sized)
 *                                     eth_session_mapping_map  (runtime sized)
 *                                     eth_session_pdrs_map     (runtime sized)
 *                                     eth_rules_match_pdr_map  (runtime sized)
 *                                     eth_egress_ifindex_map   (runtime sized)
 *                stats_maps.h      -> mc_stats_map              (fixed)
 *              This is the only entry program with runtime map configuration.
 *              rodata: MAX_UPF_INTERFACES (confirmed from skeleton grep).
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 -- PFCP Protocol
 *              3GPP TS 23.501          -- 5G System Architecture (N6 ETH)
 */
// clang-format on

/**
 * @file  n6_eth_entry_user.h
 * @brief User-space lifecycle manager for the xdp_n6_eth_entry XDP program.
 *
 * Responsibilities:
 *   - Open the xdp_n6_eth_entry_kern_c skeleton and configure its maps.
 *   - Load, attach, and link the program to the non-GTP (N6) interface.
 *   - Populate redirect_interfaces_map and upf_interface_map after load.
 *   - Expose owned maps for use by the orchestrator UPF_XDPProgram.
 *
 * Maps owned (from xdp_n6_eth_entry_kern.c includes):
 *   - upf_interface_map        (interfaces_maps.h, runtime sized)
 *   - redirect_interfaces_map  (interfaces_maps.h, runtime sized)
 *   - session_by_mac_map       (eth_pdu_maps.h,    runtime sized)
 *   - eth_session_mapping_map  (eth_pdu_maps.h,    runtime sized)
 *   - eth_session_pdrs_map     (eth_pdu_maps.h,    runtime sized)
 *   - eth_rules_match_pdr_map  (eth_pdu_maps.h,    runtime sized)
 *   - eth_egress_ifindex_map   (eth_pdu_maps.h,    runtime sized)
 *   - mc_stats_map             (stats_maps.h,      fixed)
 *
 * @note This is the only entry program that performs runtime map sizing and
 *       interface map population. It is the ETH PDU counterpart to
 * N6EntryProgram.
 */

#ifndef N6_ETH_ENTRY_USER_H_
#define N6_ETH_ENTRY_USER_H_

#include <ProgramLifeCycle.hpp>
#include <linux/bpf.h>
#include <memory>
#include <string>
#include <xdp_n6_eth_entry_skel.h>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "BPFProgram.h"
#include "interfaces_types.h"
#include "upf_network_config.h"

class BPFMaps;
class BPFMap;

using N6EthEntryLifeCycle = ProgramLifeCycle<xdp_n6_eth_entry_kern_c>;

/**
 * @class N6EthEntryProgram
 * @brief Manages the xdp_n6_eth_entry XDP program lifecycle.
 *
 * Unlike the other three entry programs, this class performs real runtime
 * map sizing (interfaces_maps.h + eth_pdu_maps.h) and populates the
 * interface maps after load.
 * Secondary entry program on the ETH PDU path (n3_eth_ is primary).
 * Not instantiated in IP PDU mode.
 *
 * Lifecycle (called from UPF_XDPProgram):
 *   1. Constructor  -- open skeleton + ConfigureMaps() (runtime sizing)
 *   2. Setup()      -- InitializeMaps() + load() + attach() +
 *                      populate redirect/iface maps + link()
 *   3. TearDown()   -- lifecycle_->tearDown()
 */
class N6EthEntryProgram : public BPFProgram {
 public:
  /**
   * @brief Constructor -- opens skeleton and configures maps.
   * @param non_gtp_interface Name of the N6 network interface.
   */
  explicit N6EthEntryProgram(const std::string& non_gtp_interface);

  /** @brief Destructor. */
  virtual ~N6EthEntryProgram();

  /**
   * @brief Load, attach, populate interface maps, and link the XDP program.
   *
   * Order: InitializeMaps() → load() → attach() →
   *        populate redirect_interfaces_map → populate upf_interface_map →
   *        link().
   */
  void Setup();

  /**
   * @brief Detach and unload the XDP program.
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
  std::shared_ptr<BPFMap> GetRedirectInterfacesMap() const;
  std::shared_ptr<BPFMap> GetSessionByMacMap() const;
  std::shared_ptr<BPFMap> GetEthSessionMappingMap() const;
  std::shared_ptr<BPFMap> GetEthSessionPdrsMap() const;
  std::shared_ptr<BPFMap> GetEthRulesMatchPdrMap() const;
  std::shared_ptr<BPFMap> GetEthEgressIfindexMap() const;
  std::shared_ptr<BPFMap> GetMacPduSessionMap() const;
  std::shared_ptr<BPFMap> GetMcStatsMap() const;
  ///@}

  /** @brief Returns the number of maps in this skeleton. */
  size_t GetMapCount() const;

  /**
   * @brief Returns the lifecycle for external orchestration by UPF_XDPProgram.
   * Resolves TODO 2 from n3_entry_user.cpp.
   */
  std::shared_ptr<N6EthEntryLifeCycle> GetLifeCycle() const {
    return lifecycle_;
  }

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
   * @brief Set max_entries for all runtime-sized maps.
   *
   * Sizes maps from interfaces_maps.h and eth_pdu_maps.h.
   * Also sets rodata->MAX_UPF_INTERFACES.
   *
   * @param skel Opened (not yet loaded) skeleton.
   */
  void ConfigureMaps(struct xdp_n6_eth_entry_kern_c* skel);

  /**
   * @brief Wrap skeleton map FDs in BPFMap objects after open.
   */
  void InitializeMaps();

  //----------------------------------------------------------------------------
  // Skeleton and lifecycle
  //----------------------------------------------------------------------------
  xdp_n6_eth_entry_kern_c* skeleton_ = nullptr;
  std::shared_ptr<N6EthEntryLifeCycle> lifecycle_;

  //----------------------------------------------------------------------------
  // Interface
  //----------------------------------------------------------------------------
  std::string non_gtp_interface_;

  //----------------------------------------------------------------------------
  // Maps
  //----------------------------------------------------------------------------
  std::shared_ptr<BPFMaps> maps_;
  /* interfaces_maps.h */
  std::shared_ptr<BPFMap> upf_interface_map_;
  std::shared_ptr<BPFMap> redirect_interfaces_map_;
  /* eth_pdu_maps.h */
  std::shared_ptr<BPFMap> session_by_mac_map_;
  std::shared_ptr<BPFMap> eth_session_mapping_map_;
  std::shared_ptr<BPFMap> eth_session_pdrs_map_;
  std::shared_ptr<BPFMap> eth_rules_match_pdr_map_;
  std::shared_ptr<BPFMap> eth_egress_ifindex_map_;
  std::shared_ptr<BPFMap> mac_pdu_session_map_;
  /* stats_maps.h */
  std::shared_ptr<BPFMap> mc_stats_map_;
};

#endif /* N6_ETH_ENTRY_USER_H_ */
