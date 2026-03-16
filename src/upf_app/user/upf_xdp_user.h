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
 * Changes:     Boy Scout cleanup — changelog, Doxygen improvements.
 *              V17.10.0 harmonisation:
 *                - Added "session_rules_enabled_map" alias to GetMapByName()
 *                  docstring (renamed from session_qos_enabled_map in the
 *                  rules-enabled-flags refactor).
 *                - Documented missing maps in GetMapByName() alias table:
 *                  urr_config_map, urr_volume_map, bar_config_map,
 *                  bar_state_map, mar_rules_map, feature_dispatch_map.
 *                - Clarified that @note "Follows Google C++ Style Guide"
 *                  adds no information; removed from @class block.
 *                - Removed `extern upf_config upf_cfg` forward-declaration
 *                  note (upf_cfg access moved to upf_xdp_user.cpp only; the
 *                  header need not mention it).
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 *              3GPP TS 23.501          (Release 17)           — 5G System Arch.
 */
// clang-format on

/**
 * @file upf_xdp_user.h
 * @brief XDP pipeline manager for UPF packet processing
 * @author OpenAirInterface, Franck Messaoudi
 * @date 2025 / 2026-03
 *
 * UPF_XDPProgram manages the complete BPF tail-call pipeline for fast-path
 * packet processing.  The monolithic XDP program has been decomposed into
 * modular stages connected via BPF PROG_ARRAY tail calls.
 *
 * Pipeline Architecture
 * ---------------------
 *   Entry (N3/N6) → Session Lookup → PDR Match → FAR
 *                                              └→ QER → URR → MAR
 *                                                          └→ BAR (terminal)
 *
 * Entry Points (selected by PipelineFeatureFlags::pdu_type)
 * ----------------------------------------------------------
 *   IP PDU:  upf_n3_entry  on N3,  upf_n6_entry  on N6
 *   ETH PDU: upf_n3_eth_entry on N3, upf_n6_eth_entry on N6
 *
 * PROG_ARRAY Slots (feature_dispatch_map)
 * ----------------------------------------
 *   0  PROG_SESSION_LOOKUP  — always loaded (ip or eth variant)
 *   1  PROG_PDR_MATCH       — always loaded
 *   2  PROG_FAR             — always loaded
 *   3  PROG_QER             — loaded when enable_qos
 *   4  PROG_URR             — loaded when enable_urr
 *   5  PROG_BAR             — loaded when enable_bar
 *   6  PROG_MAR             — loaded when enable_mar
 *   7  PROG_FRAMED_ROUTING  — loaded when enable_framed_routing
 *   8  PROG_ETH_PDU_BROADCAST — loaded when ETH PDU type
 *
 * All programs share maps via BTF map linking (same name+type = same map).
 * Per-packet context is passed via BPF_MAP_TYPE_PERCPU_ARRAY (zero overhead).
 *
 * BPF Maps Managed:
 *   - packet_ctx_map: Per-CPU scratch for inter-stage context
 *   - feature_dispatch_map: PROG_ARRAY for tail calls
 *   - session_by_ue_ip_map: UE IP → Session ID mapping
 *   - session_by_mac_map: UE MAC → Session ID (ETH PDU only)
 *   - arp_table_map: ARP resolution table
 *   - redirect_interfaces_map: Interface redirection
 *   - upf_interface_map: UPF reference points (N3, N4, N6)
 *   - pdrs_per_session_map: PDRs for each session
 *   - rules_match_pdr_map: Rule matching state
 *   - sdf_filters_map: SDF filter definitions
 *   - session_qos_enabled_map: QoS enablement per session
 *   - framed_route_mapping: Framed routing mappings
 *
 * XDP Performance:
 * - Native/Driver mode: Best performance, hardware offload
 * - SKB mode: Fallback, compatibility
 * - Typical throughput: 10-40 Gbps depending on hardware
 *
 * Reference Standards:
 *   - Linux XDP: kernel.org/doc/html/latest/networking/af_xdp.html
 *   - 3GPP TS 29.281: GTP-U protocol
 *   - 3GPP TS 29.244: PFCP protocol for session management
 *   - 3GPP TS 23.501: 5G System Architecture (N3, N6 interfaces)
 *
 * @note This implementation follows Google C++ Style Guide
 */

#ifndef UPF_XDP_USER_H_
#define UPF_XDP_USER_H_

#include <ProgramLifeCycle.hpp>
#include <linux/bpf.h>
#include <memory>
#include <string>
#include <upf_xdp_kern_skel.h>
#include <wrappers/BPFMap.hpp>
#include "interfaces.h"
#include <framed_routing_bpf.h>
#include "upf_network_config.h"  // upf::g_net_cfg — no upf_config.hpp needed
#include "BPFProgram.h"

// Forward declarations
class BPFMaps;
class BPFMap;

// ==========================================================================
// Pipeline configuration types
// ==========================================================================

// PduSessionType, PipelineFeatureFlags, and ProgIndex are defined in
// include/upf_pipeline_config.h — visible to control/, user/, and kernel/
// without any cross-folder dependency or generated-skeleton dependency.
#include "upf_pipeline_config.h"

/**
 * @brief Type alias for XDP program lifecycle management
 *
 * Manages the complete lifecycle of the XDP kernel program:
 * open → load → attach → link → teardown
 */
using UPF_XDPProgramLifeCycle = ProgramLifeCycle<upf_xdp_kern_c>;

// ==========================================================================
// UPF_XDPProgram
// ==========================================================================

/**
 * @class UPF_XDPProgram
 * @brief Manages the BPF tail-call pipeline for UPF packet processing
 *
 * Owns the upf_xdp_kern_c skeleton which contains all pipeline programs.
 * Provides:
 *   - Skeleton open / load / attach lifecycle
 *   - Entry program selection (IP PDU vs ETH PDU)
 *   - PROG_ARRAY population (feature_dispatch_map)
 *   - BPF map wrappers for all pipeline maps
 *   - Network interface configuration (N3/N4/N6 maps)
 *   - ARP table and framed routing helpers
 *
 * The constructor reads all config from upf::g_net_cfg — no upf_config
 * argument required.  upf::g_net_cfg must be populated before construction
 * (guaranteed by control/Configuration.cpp running first).
 *
 * Lifecycle:
 *   1. Construct: supply N3/N6 interface names
 *   2. Setup(flags): open skeleton, load, attach, populate PROG_ARRAY,
 *                    link entry programs to interfaces
 *   3. Runtime: maps managed by SessionProgramManager
 *   4. TearDown: detach programs, destroy skeleton
 *
 * Thread Safety: Not thread-safe.  Create and Setup from a single thread.
 *
 * XDP Modes:
 * - XDP_FLAGS_DRV_MODE: Driver mode (best performance, hardware offload)
 * - XDP_FLAGS_SKB_MODE: SKB mode (fallback, compatibility)
 *
 * @note Inherits from BPFProgram base class
 */
class UPF_XDPProgram : public BPFProgram {
 public:
  /**
   * @brief Constructor
   *
   * Stores interface names and prepares the lifecycle manager.  Does NOT
   * open or load the skeleton — call Setup() for that.
   *
   * Network addresses (N3 IP, N6 IP, DN IP) are read from upf::g_net_cfg
   * automatically during Setup().
   *
   * @param gtp_interface  N3 (GTP-U) interface name, e.g. "n3"
   * @param non_gtp_interface  N6 (Data Network) interface name, e.g. "n6"
   *
   * @throws std::runtime_error if skeleton open fails in the lifecycle ctor
   */
  explicit UPF_XDPProgram(
      const std::string& gtp_interface, const std::string& non_gtp_interface);

  /**
   * @brief Destructor - cleans up XDP program resources
   *
   * Detaches XDP programs from interfaces and frees BPF resources.
   * Maps are automatically cleaned up by the kernel.
   */
  virtual ~UPF_XDPProgram();

  // ==========================================================================
  // Lifecycle
  // ==========================================================================

  /**
   * @brief Setup tail-call pipeline and attach to interfaces
   *
   * Complete pipeline initialisation:
   *   1. Open skeleton; configure map max_entries from upf::g_net_cfg
   *   2. Load all programs into kernel
   *   3. Attach programs to hooks
   *   4. Initialise BPF map wrappers (InitializeMaps)
   *   5. Configure egress interface map (UPLINK→N6, DOWNLINK→N3)
   *   6. Write upf_interface_map entries for N3, N4, N6
   *   7. Populate feature_dispatch_map (PopulateProgramArray)
   *   8. Link entry programs to N3/N6 based on flags.pdu_type
   *
   * Entry program selection (flags.pdu_type):
   *   IP PDU:  upf_n3_entry  → N3 interface
   *            upf_n6_entry  → N6 interface
   *   ETH PDU: upf_n3_eth_entry → N3 interface
   *            upf_n6_eth_entry → N6 interface
   *
   * @param flags  Feature flags (QER/URR/BAR/MAR/framed_routing, pdu_type)
   *
   * @throws std::runtime_error on interface lookup failure, XDP attach failure,
   *                            or PROG_ARRAY population failure
   */
  void Setup(const PipelineFeatureFlags& flags);

  /**
   * @brief Teardown pipeline and release all resources
   * @note Safe to call multiple times
   */
  void TearDown();

  // ==========================================================================
  // PROG_ARRAY Management
  // ==========================================================================

  /**
   * @brief Populate feature_dispatch_map from feature flags
   *
   * Inserts BPF program FDs at the slot indices defined by ProgIndex.
   * Slots for disabled features are left empty (tail_call → no-op).
   *
   * @param flags  Feature flags controlling which slots are populated
   * @throws std::runtime_error if a mandatory slot cannot be inserted
   */
  void PopulateProgramArray(const PipelineFeatureFlags& flags);

  /**
   * @brief Remove a key from the tail-call program map
   * @param key  Program map key (typically session ID or slot index)
   */
  void RemoveProgramMap(uint32_t key);

  /**
   * @brief Get file descriptor for a BPF program section by name
   *
   * @param section_name  BPF program section/function name
   * @return int  Program FD, or -1 if not found
   */
  int GetProgramFd(const char* section_name) const;

  // ==========================================================================
  // Map Access — generic
  // ==========================================================================

  /** @return All BPF maps container */
  std::shared_ptr<BPFMaps> GetMaps();

  /**
   * @brief Get BPF map by name (with alias support)
   *
   * Supported names (aliases listed after →):
   *   "session_map" / "session_by_ue_ip_map" → UE IP→session mapping
   *   "session_by_mac_map"                   → ETH PDU MAC→session mapping
   *   "arp_table" / "arp_table_map"          → ARP resolution
   *   "redirect_interfaces_map"              → Egress interface IDs
   *   "upf_interface_map"                    → N3/N4/N6 reference points
   *   "pdrs_per_session_map"                 → PDR arrays per session
   *   "rules_match_pdr_map"                  → PDR → rule associations
   *   "sdf_filters_map"                      → SDF 5-tuple filter defs
   *   "session_qos_enabled_map" /
   *   "session_rules_enabled_map"            → Rules-enabled flags per session
   *                                            (both names accepted; map was
   *                                            renamed from the former to the
   *                                            latter in the
   * rules-enabled-flags refactor) "m_framed_route_mapping"               →
   * Framed route table "framed_routing_flag"                  → Framed routing
   * enable flag "feature_dispatch_map"                 → PROG_ARRAY for tail
   * calls "urr_config_map"                       → URR configuration
   *   "urr_volume_map"                       → URR volume counters
   *   "bar_config_map"                       → BAR configuration
   *   "bar_state_map"                        → BAR DDN runtime state
   *   "mar_rules_map"                        → MAR steering rules
   *
   * @return nullptr if not found (logs a warning)
   */
  std::shared_ptr<BPFMap> GetMapByName(const std::string& map_name);

  // ==========================================================================
  // Interface Configuration
  // ==========================================================================

  /**
   * @brief Write an entry into upf_interface_map for a reference point
   *
   * Reads IP/port from upf::g_net_cfg — no upf_config access needed.
   *
   * @param reference_point  N3_INTERFACE / N4_INTERFACE / N6_INTERFACE
   *
   * Reference Points (3GPP TS 23.501):
   * - N3: Interface between RAN and UPF (GTP-U)
   * - N4: Interface between SMF and UPF (PFCP)
   * - N6: Interface between UPF and Data Network
   * - N9: Interface between UPFs (for uplink classifier)
   * - N19: Interface between SMF and UPF (policy control)
   */
  void CreateUpfInterfaceMapEntry(reference_point_t reference_point);

  // ==========================================================================
  // Framed Routing
  // ==========================================================================

  std::shared_ptr<BPFMap> GetFramedRouteMappingMap();
  void UpdateFramedRouteMappingMap(uint32_t ue_ip, FramedRoutingKeyBPF key);
  void RemoveFramedRoute(FramedRoutingKeyBPF key);
  void SetFramedRouting(bool enable);

  // ==========================================================================
  // Direct Map Getters (for performance)
  // ==========================================================================

  std::shared_ptr<BPFMap> GetEgressInterfaceMap() const;
  std::shared_ptr<BPFMap> GetArpTableMap() const;
  std::shared_ptr<BPFMap> GetIfaceMap() const;
  std::shared_ptr<BPFMap> GetSessionMappingMap() const;
  std::shared_ptr<BPFMap> GetSessionMacMap() const;  ///< ETH PDU only
  std::shared_ptr<BPFMap> GetRulesMatchPdrMap() const;
  std::shared_ptr<BPFMap> GetSessionPdrsMap() const;
  std::shared_ptr<BPFMap> GetSdfFilterMap() const;
  std::shared_ptr<BPFMap> GetQosEnablingMap() const;
  std::shared_ptr<BPFMap> GetFeatureDispatchMap() const;

  // ==========================================================================
  // Pipeline Status and Statistics
  // ==========================================================================

  /**
   * @brief Get total number of BPF maps in the pipeline
   */
  size_t GetMapCount() const;

  /**
   * @brief Check if interface is using native XDP (driver mode)
   */
  bool IsNativeXdp(const std::string& interface) const;

  /**
   * @brief Get XDP mode string for display ("Native" or "SKB")
   */
  std::string GetXdpModeString(const std::string& interface) const;

  /**
   * @brief Get configured PDU session type
   */
  PduSessionType GetPduSessionType() const { return pdu_session_type_; }

  /**
   * @brief Get current pipeline feature flags
   */
  const PipelineFeatureFlags& GetFeatureFlags() const { return features_; }

 private:
  // ==========================================================================
  // Internal Initialization
  // ==========================================================================

  /**
   * @brief Initialize all BPF map wrappers
   *
   * Called after skeleton open and before load.  Wrappers for pipeline-shared
   * maps (urr_config_map, bar_config_map, mar_rules_map, etc.) are created
   * here so URRProgram / BARProgram / MARProgram can receive them.
   */
  void InitializeMaps();

  /**
   * @brief Configure map max_entries from upf::g_net_cfg sizing parameters
   *
   * Called during open (before load) to set map capacities.
   *
   * @param skel  Opened skeleton pointer
   * @throws std::runtime_error on invalid configuration
   */
  void ConfigurePfcpSessionLookupMaps(struct upf_xdp_kern_c* skel);

  /**
   * @brief Insert one BPF program FD into feature_dispatch_map
   *
   * @param index PROG_ARRAY slot index (enum ProgIndex)
   * @param section_name BPF program section name
   * @return true if inserted successfully, false on error
   */
  bool InsertProgramSlot(uint32_t index, const char* section_name);

  // ==========================================================================
  // Member Variables
  // ==========================================================================

  // Skeleton and lifecycle
  upf_xdp_kern_c* skeleton_;  ///< BPF skeleton (libbpf)
  std::shared_ptr<UPF_XDPProgramLifeCycle> lifecycle_;  ///< Lifecycle manager

  // Interface configuration names (N3 / N6)
  std::string gtp_interface_;      ///< GTP-U interface name (N3)
  std::string non_gtp_interface_;  ///< NON-GTP interface name (N6)

  // Pipeline configuration
  PduSessionType pdu_session_type_;  ///< IP or ETH PDU sessions
  PipelineFeatureFlags features_;    ///< Current feature flags

  // Map container
  std::shared_ptr<BPFMaps> maps_;  ///< All BPF maps container

  // --- Individual map pointers (fast access) ---

  // Session lookup maps
  std::shared_ptr<BPFMap> session_mapping_map_;  ///< UE IP  → SEID (IP PDU)
  std::shared_ptr<BPFMap> session_mac_map_;      ///< UE MAC → SEID (ETH PDU)

  // Individual map pointers (for fast access)
  std::shared_ptr<BPFMap> teid_session_map_;  ///< TEID to session mapping
  // Interface maps
  std::shared_ptr<BPFMap> egress_interface_map_;  ///< FlowDir → ifindex
  std::shared_ptr<BPFMap> arp_table_map_;         ///< IP → MAC (ARP)
  std::shared_ptr<BPFMap> upf_iface_map_;         ///< N3/N4/N6 reference pts

  // PDR matching maps
  std::shared_ptr<BPFMap> session_pdrs_map_;     ///< SEID → ordered PDR list
  std::shared_ptr<BPFMap> rules_match_pdr_map_;  ///< (SEID,PDR) → rule IDs
  std::shared_ptr<BPFMap> sdf_filter_map_;       ///< (SEID,PDR) → SDF tuple

  // QoS / rule enablement
  std::shared_ptr<BPFMap> qos_enabling_map_;  ///< SEID → rules_enabled flags

  // URR maps
  std::shared_ptr<BPFMap> urr_config_map_;  ///< (SEID,URR) → pfcp_urr
  std::shared_ptr<BPFMap> urr_volume_map_;  ///< (SEID,URR) → counters

  // BAR maps
  std::shared_ptr<BPFMap> bar_config_map_;  ///< (SEID,BAR) → pfcp_bar
  std::shared_ptr<BPFMap> bar_state_map_;   ///< (SEID,BAR) → ddn state

  // MAR maps
  std::shared_ptr<BPFMap> mar_rules_map_;  ///< (SEID,MAR) → pfcp_mar

  // Framed routing
  std::shared_ptr<BPFMap> framed_route_mapping_map_;
  std::shared_ptr<BPFMap> framed_route_flag_map_;

  // PROG_ARRAY
  std::shared_ptr<BPFMap> feature_dispatch_map_;  ///< Tail-call program array

  // Per-CPU packet context (managed by kernel, no explicit user-space writes)
  std::shared_ptr<BPFMap> packet_ctx_map_;
};

#endif  // UPF_XDP_USER_H_
