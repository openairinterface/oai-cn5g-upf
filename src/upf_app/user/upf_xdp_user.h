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
 * Changes:     Refactored from monolithic upf_xdp_kern_c to split-skeleton
 *              architecture.
 *              Primary skeleton is ALWAYS xdp_n3_entry_kern_c (it owns
 *              the infrastructure maps: upf_interface_map,
 *              redirect_interfaces_map, arp_table_map which
 *              xdp_n3_eth_entry_kern_c does NOT have). PDU type controls
 *              which programs are ATTACHED to interfaces, not which
 *              skeleton creates the shared map FDs.
 *              All upf_cfg references removed -- sizing uses upf:: getters
 *              from upf_network_config.h exclusively.
 *              Stage programs use XDPStageProgram<> base template.
 *              GetMapByName() preserved for SessionProgramManager compat.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 -- PFCP Protocol
 *              3GPP TS 23.501          -- 5G System Architecture
 */
// clang-format on

/**
 * @file  upf_xdp_user.h
 * @brief XDP pipeline orchestrator for UPF fast-path packet processing.
 * @author OpenAirInterface, Franck Messaoudi
 * @date 2025 / 2026-03
 *
 * UPF_XDPProgram owns the 4 entry skeletons and the 7 infrastructure maps
 * created by xdp_n3_entry_kern (the primary skeleton).
 *
 * Primary skeleton: xdp_n3_entry_kern_c -- ALWAYS, regardless of PDU type.
 *   Reason: it is the only entry skeleton that has upf_interface_map,
 *   redirect_interfaces_map, and arp_table_map. These infrastructure maps
 *   are needed by all pipeline stages. xdp_n3_eth_entry_kern_c does NOT
 *   have them.
 *
 * PDU type effect (from PipelineFeatureFlags::pdu_type):
 *   IP      -- attach xdp_n3_entry + xdp_n6_entry to N3/N6
 *   Ethernet-- attach xdp_n3_eth_entry + xdp_n6_eth_entry to N3/N6
 *   In both cases all 4 entry skeletons are LOADED (for map sharing);
 *   only the attachment step differs.
 *
 * Infrastructure maps owned (from xdp_n3_entry_kern_c skeleton):
 *   packet_context_map, tail_call_progs_map, upf_interface_map,
 *   redirect_interfaces_map, arp_table_map, session_rules_enabled_map,
 *   mc_stats
 *
 * Pipeline stage programs (each inherits XDPStageProgram<T>):
 *   SessionLookupIPProgram  -- slot 0, owns IP session maps
 *   SessionLookupETHProgram -- slot 1, owns ETH session maps
 *   PdrMatchProgram         -- slot 2, owns sdf_filters_map
 *   FARProgram              -- slot 3, no unique maps
 *   QERProgram              -- slot 4, TC-BPF, owns its own maps
 *   URRProgram              -- slot 5, owns urr_config_map +
 * urr_volume_counters_map BARProgram              -- slot 6, owns
 * bar_config_map + bar_state_map MARProgram              -- slot 7, owns
 * mar_config_map + mar_access_state_map
 */

#ifndef UPF_XDP_USER_H_
#define UPF_XDP_USER_H_

#include <ProgramLifeCycle.hpp>
#include <linux/bpf.h>
#include <memory>
#include <string>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include <BPFProgram.h>
#include "upf_pipeline_config.h"
#include "upf_network_config.h" /* upf::Get*() -- no upf_config.hpp */
#include "interfaces_types.h"
#include "framed_routing_bpf.h"

/* Entry program skeletons */
#include <xdp_n3_entry_skel.h>
#include <xdp_n6_entry_skel.h>
#include <xdp_n3_eth_entry_skel.h>
#include <xdp_n6_eth_entry_skel.h>

/* Pipeline stage program headers */
#include "session_lookup_ip_user.h"
#include "session_lookup_eth_user.h"
#include "pdr_match_user.h"
#include "far_apply_user.h"
#include "qer_tc_user.h"
#include "urr_apply_user.h"
#include "bar_apply_user.h"
#include "mar_apply_user.h"

class BPFMaps;
class BPFMap;

using UPF_XDPProgramLifeCycle = ProgramLifeCycle<xdp_n3_entry_kern_c>;

// ==========================================================================
// UPF_XDPProgram
// ==========================================================================

class UPF_XDPProgram : public BPFProgram {
 public:
  // ==========================================================================
  // Constructor / Destructor
  // ==========================================================================

  explicit UPF_XDPProgram(
      const std::string& gtp_interface, const std::string& non_gtp_interface);
  virtual ~UPF_XDPProgram();

  // ==========================================================================
  // Lifecycle
  // ==========================================================================

  void Setup(const PipelineFeatureFlags& flags);
  void TearDown();
  void RemoveProgramMap(uint32_t key);

  // ==========================================================================
  // Map access
  // ==========================================================================

  std::shared_ptr<BPFMaps> GetMaps();
  std::shared_ptr<BPFMap> GetMapByName(const std::string& map_name);

  // ==========================================================================
  // Interface configuration
  // ==========================================================================

  void CreateUpfInterfaceMapEntry(reference_point_t reference_point);

  // ==========================================================================
  // Framed routing
  // ==========================================================================

  std::shared_ptr<BPFMap> GetFramedRouteMappingMap();
  void UpdateFramedRouteMappingMap(uint32_t ue_ip, FramedRoutingKeyBPF key);
  void RemoveFramedRoute(FramedRoutingKeyBPF key);
  void SetFramedRouting(bool enable);

  // ==========================================================================
  // Direct map getters -- infrastructure (n3_entry_kern)
  // ==========================================================================

  std::shared_ptr<BPFMap> GetEgressInterfaceMap() const {
    return egress_interface_map_;
  }
  std::shared_ptr<BPFMap> GetArpTableMap() const { return arp_table_map_; }
  std::shared_ptr<BPFMap> GetIfaceMap() const { return upf_iface_map_; }
  std::shared_ptr<BPFMap> GetTailCallProgsMap() const {
    return tail_call_progs_map_;
  }
  std::shared_ptr<BPFMap> GetPacketContextMap() const {
    return packet_ctx_map_;
  }
  std::shared_ptr<BPFMap> GetSessionRulesEnabledMap() const {
    return session_rules_map_;
  }
  std::shared_ptr<BPFMap> GetMcStatsMap() const { return mc_stats_map_; }

  // ==========================================================================
  // Direct map getters -- delegated to stage programs
  // ==========================================================================

  std::shared_ptr<BPFMap> GetSessionMappingMap() const;
  std::shared_ptr<BPFMap> GetSessionMacMap() const;
  std::shared_ptr<BPFMap> GetRulesMatchPdrMap() const;
  std::shared_ptr<BPFMap> GetSessionPdrsMap() const;
  std::shared_ptr<BPFMap> GetSdfFilterMap() const;
  std::shared_ptr<BPFMap> GetQosEnablingMap() const;
  std::shared_ptr<BPFMap> GetFeatureDispatchMap() const;

  // ==========================================================================
  // Pipeline stage program accessors
  // ==========================================================================

  std::shared_ptr<SessionLookupIPProgram> GetSessionLookupIPProgram() const {
    return sl_ip_;
  }
  std::shared_ptr<SessionLookupETHProgram> GetSessionLookupETHProgram() const {
    return sl_eth_;
  }
  std::shared_ptr<PdrMatchProgram> GetPdrMatchProgram() const { return pdr_; }
  std::shared_ptr<FARProgram> GetFarProgram() const { return far_; }
  std::shared_ptr<QERProgram> GetQerProgram() const { return qer_; }
  std::shared_ptr<URRProgram> GetUrrProgram() const { return urr_; }
  std::shared_ptr<BARProgram> GetBarProgram() const { return bar_; }
  std::shared_ptr<MARProgram> GetMarProgram() const { return mar_; }

  // ==========================================================================
  // Status
  // ==========================================================================

  size_t GetMapCount() const;
  bool IsNativeXdp(const std::string& iface) const;
  std::string GetXdpModeString(const std::string& iface) const;

 private:
  // ==========================================================================
  // Internal helpers
  // ==========================================================================

  /** @brief Configure n3_entry's infrastructure map max_entries. */
  void ConfigureEntryMaps(struct xdp_n3_entry_kern_c* skel);

  /** @brief Share all common map FDs from src_obj to dst_obj by name. */
  void ShareMaps(struct bpf_object* src_obj, struct bpf_object* dst_obj);

  /** @brief Wrap n3_entry's 7 map FDs in BPFMap objects. */
  void InitializeMaps();

  bool InsertProgramSlot(uint32_t index, struct bpf_program* prog);
  void PopulateProgramArray(const PipelineFeatureFlags& flags);

  // ==========================================================================
  // Entry skeletons -- n3_entry is always primary
  // ==========================================================================

  xdp_n3_entry_kern_c* skel_n3_ = nullptr;  ///< Primary -- always loaded
  xdp_n6_entry_kern_c* skel_n6_ = nullptr;
  xdp_n3_eth_entry_kern_c* skel_n3_eth_ = nullptr;
  xdp_n6_eth_entry_kern_c* skel_n6_eth_ = nullptr;

  // ==========================================================================
  // Pipeline stage programs
  // ==========================================================================

  std::shared_ptr<SessionLookupIPProgram> sl_ip_;
  std::shared_ptr<SessionLookupETHProgram> sl_eth_;
  std::shared_ptr<PdrMatchProgram> pdr_;
  std::shared_ptr<FARProgram> far_;
  std::shared_ptr<QERProgram> qer_;
  std::shared_ptr<URRProgram> urr_;
  std::shared_ptr<BARProgram> bar_;
  std::shared_ptr<MARProgram> mar_;

  // ==========================================================================
  // Interface names and feature flags
  // ==========================================================================

  std::string gtp_interface_;
  std::string non_gtp_interface_;
  PipelineFeatureFlags features_;

  // ==========================================================================
  // Infrastructure maps -- owned by n3_entry_kern skeleton
  // ==========================================================================

  std::shared_ptr<BPFMaps> maps_;

  std::shared_ptr<BPFMap> packet_ctx_map_;        ///< packet_context_map
  std::shared_ptr<BPFMap> tail_call_progs_map_;   ///< tail_call_progs_map
  std::shared_ptr<BPFMap> upf_iface_map_;         ///< upf_interface_map
  std::shared_ptr<BPFMap> egress_interface_map_;  ///< redirect_interfaces_map
  std::shared_ptr<BPFMap> arp_table_map_;         ///< arp_table_map
  std::shared_ptr<BPFMap> session_rules_map_;     ///< session_rules_enabled_map
  std::shared_ptr<BPFMap> mc_stats_map_;          ///< mc_stats
};

#endif /* UPF_XDP_USER_H_ */