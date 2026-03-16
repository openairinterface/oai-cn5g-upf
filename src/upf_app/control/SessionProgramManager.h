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

/**
 * @file SessionProgramManager.h
 * @brief BPF Program Manager for PFCP Sessions
 * @author OpenAirInterface
 * @date 2025
 *
 * This module manages BPF/eBPF programs and maps for PFCP session processing
 * in the user plane data path. It handles the translation between PFCP IEs
 * and BPF data structures.
 *
 * Tail Call Architecture:
 *   Entry -> Session Lookup -> PDR Match -> FAR -> [QER] -> [URR] -> [BAR] ->
 * [MAR] Programs in brackets conditional on RULE_*_ENABLED flags in
 *   session_rules_enabled_map (replaces old session_qos_enabled_map).
 *
 * ETH PDU Session Support (TS 23.501 Section 5.6.10.3):
 *   ETH sessions keyed by TEID (not UE IP), use separate BPF maps:
 *   eth_session_mapping_map, eth_session_pdrs_map, eth_rules_match_pdr_map
 * Key 3GPP References:
 * - 3GPP TS 29.244: PFCP protocol specification
 * - 3GPP TS 29.281: GTPv1-U protocol for tunneling
 * - 3GPP TS 23.501: 5G System Architecture
 * - 3GPP TS 29.244 Section 8.2: Information Elements for PDR, FAR, QER
 * - 3GPP TS 29.244 Section 8.2.74: Outer Header Creation
 */

#ifndef SESSION_PROGRAM_MANAGER_H_
#define SESSION_PROGRAM_MANAGER_H_

#include <cstdint>
#include <array>
#include <map>
#include <memory>
#include <mutex>
#include <vector>
#include <set>

// Forward declarations
namespace pfcp {
class pfcp_session;
class pfcp_pdr;
class pfcp_far;
class pfcp_qer;
class pfcp_urr;
class pfcp_bar;
class pfcp_mar;
}  // namespace pfcp

class BpfMap;
class ISessionObserver;
class UPF_XDPProgram;
class QERProgram;
class SessionPrograms;
struct pfcp_pdr;
struct pfcp_far;
struct pfcp_qer;
struct pfcp_urr;
struct pfcp_bar;
struct pfcp_mar;

/**
 * @struct PfcpProgramInfo
 * @brief Associates PFCP session with BPF program
 */
struct PfcpProgramInfo {
  uint64_t seid;                                ///< Session Endpoint ID
  std::shared_ptr<UPF_XDPProgram> xdp_program;  ///< Associated XDP program

  PfcpProgramInfo() : seid(0), xdp_program(nullptr) {}
};

/**
 * @class SessionProgramManager
 * @brief Manages BPF programs and maps for PFCP sessions
 *
 * This manager is responsible for:
 * - Converting PFCP IEs to BPF structures (3GPP TS 29.244 Section 8.2)
 * - Managing BPF maps for PDR/FAR/QER rules
 * - Updating ARP tables for next-hop resolution
 * - Synchronizing session state with data path
 *
 * Thread Safety: All public methods are thread-safe.
 *
 * @note Follows Google C++ Style Guide
 */

// PduSessionType is defined in include/upf_pipeline_config.h
#include "upf_pipeline_config.h"

class SessionProgramManager {
 public:
  /**
   * @brief Destructor - cleans up all programs and sessions
   */
  virtual ~SessionProgramManager();

  /**
   * @brief Get singleton instance
   *
   * @return Reference to singleton instance
   *
   * @deprecated Use dependency injection in new code
   * @note Singleton pattern maintained for backward compatibility
   */
  static SessionProgramManager& GetInstance();

  // ==========================================================================
  // Session Lifecycle Management
  // ==========================================================================

  /**
   * @brief Create a new session program
   * @param seid Session Endpoint Identifier
   */
  void CreateSession(uint64_t seid);

  /**
   * @brief Remove session and its associated programs
   *
   * Cleans up all BPF maps for this session:
   * - session_rules_enabled_map (tail call skip-chain flags)
   * - ETH-specific maps if Ethernet PDU session
   * - urr_config_map, urr_volume_map (usage reporting state)
   * - bar_config_map, bar_state_map (buffering state)
   * - mar_rules_map (ATSSS steering)
   * - QER TC-BPF program (if instantiated)
   * - ARP caches for N3/N6 endpoints
   *
   * @param seid Session Endpoint Identifier
   */
  void RemoveSession(uint64_t seid);

  /**
   * @brief Remove all sessions and clean up all resources
   */
  void RemoveAllSessions();

  // ==========================================================================
  // BPF Map Management
  // ==========================================================================

  /**
   * @brief Set the TEID session map
   * @param map Shared pointer to BPF map
   */
  void SetTeidSessionMap(std::shared_ptr<BpfMap> map);

  /**
   * @brief Set the ARP table map
   * @param map Shared pointer to BPF map for ARP entries
   * @see RFC 826 - Address Resolution Protocol
   */
  void SetArpTableMap(std::shared_ptr<BpfMap> map);

  /**
   * @brief Store IP PDU session information in BPF map
   *
   * Updates the session_by_ue_ip_map with UE IP, TEIDs, and SEID.
   * For IP PDU sessions only — ETH PDU uses StoreEthPduSessionInMap().
   *
   * If an entry already exists for this UE IP, missing TEIDs are
   * filled in (supports split Create/Modify where UL and DL TEIDs
   * arrive in separate PFCP messages).
   *
   * @param xdp_program XDP program containing the maps
   * @param ue_ip UE IP address
   * @param teid_dl Downlink TEID (3GPP TS 29.281)
   * @param teid_ul Uplink TEID (3GPP TS 29.281)
   * @param seid Session Endpoint Identifier
   *
   * @see 3GPP TS 29.281 - GTPv1-U
   */
  void StorePduSessionInMap(
      std::shared_ptr<UPF_XDPProgram> xdp_program, uint32_t ue_ip,
      uint32_t teid_dl, uint32_t teid_ul, uint64_t seid);

  /**
   * @brief Store ETH PDU session information in BPF map
   *
   * Updates eth_session_mapping_map with TEID -> eth_session_id mapping.
   * Used for Ethernet PDU sessions (3GPP TS 23.501 Section 5.6.10.3)
   * which are keyed by TEID rather than UE IP address.
   *
   * @param xdp_program XDP program containing the maps
   * @param teid_ul Uplink TEID (key in eth_session_mapping_map)
   * @param teid_dl Downlink TEID (for GTP-U encap toward gNB)
   * @param gnb_ip gNodeB IPv4 address (for DL outer header creation)
   * @param seid Session Endpoint Identifier
   *
   * @see 3GPP TS 23.501 Section 5.6.10.3 - Ethernet PDU Session Type
   * @see 3GPP TS 29.281 - GTPv1-U
   */
  void StoreEthPduSessionInMap(
      std::shared_ptr<UPF_XDPProgram> xdp_program, uint32_t teid_ul,
      uint32_t teid_dl, uint32_t gnb_ip, uint64_t seid);

  // ==========================================================================
  // Pipeline Management
  // Reference: 3GPP TS 29.244 Section 5.2 - PFCP Session procedures
  // ==========================================================================

  // ---- Tail Call Rule Enable Flags (NEW) ----

  /**
   * @brief Compute rules_enabled bitmask from session content
   *
   * Examines the PFCP session's PDRs and FARs to determine which
   * downstream tail call programs should be active:
   *   - QER present in any PDR -> RULE_QER_ENABLED
   *   - URR present in any PDR -> RULE_URR_ENABLED
   *   - BAR associated with any FAR -> RULE_BAR_ENABLED
   *   - MAR present in any PDR -> RULE_MAR_ENABLED
   *
   * The result is stored in session_rules_enabled_map and cached in
   * pctx->rules_enabled by the session lookup BPF program.
   *
   * @param session PFCP session to analyze
   * @return Bitmask of RULE_*_ENABLED flags
   *
   * @see rules_enabled_flags.h for flag definitions
   * @see 3GPP TS 29.244 Section 7.2.2 - PFCP Session Establishment
   */
  uint32_t ComputeRulesEnabledFlags(
      std::shared_ptr<pfcp::pfcp_session> session) const;

  /**
   * @brief Update session_rules_enabled_map for a session
   *
   * Stores the computed rules_enabled bitmask in the BPF map so that
   * the tail call skip-chain dispatch can bypass disabled programs
   * at zero cost (no tail call for disabled rule types).
   *
   * @param xdp_program XDP program containing the map
   * @param seid Session Endpoint Identifier (map key)
   * @param flags Bitmask of RULE_*_ENABLED flags (map value)
   *
   * @see rules_enabled_flags.h for flag definitions
   * @see tail_call_dispatch.h for skip-chain implementation
   */
  void UpdateRulesEnabledMap(
      std::shared_ptr<UPF_XDPProgram> xdp_program, uint64_t seid,
      uint32_t flags);

  // ---- PDU Session Type Detection (NEW) ----

  /**
   * @brief Detect whether a PFCP session is IP or Ethernet PDU type
   *
   * Determines BPF map routing based on PDU session type:
   * - IP PDU sessions use UE IP-keyed maps (session_by_ue_ip_map)
   * - ETH PDU sessions use TEID-keyed maps (eth_session_mapping_map)
   *
   * Detection heuristic (3GPP TS 23.501 Section 5.6.10.3):
   *   1. If any PDR contains a UE IP Address IE -> IP PDU
   *   2. If no PDR has UE IP (all use F-TEID only) -> Ethernet PDU
   *
   * @param session PFCP session to check
   * @return PduSessionType::Ethernet if ETH PDU, PduSessionType::IP otherwise
   *
   * @note Future: use explicit PDU Session Type IE from PFCP Session
   *       Establishment Request (3GPP TS 29.244 Section 8.2.124)
   * @see 3GPP TS 23.501 Section 5.6.10.3 - Ethernet PDU Session Type
   */
  PduSessionType DetectPduSessionType(
      std::shared_ptr<pfcp::pfcp_session> session) const;

  // Pipeline Management

  /**
   * @brief Create complete BPF pipeline for a session
   *
   * Sets up all BPF maps and programs needed to process packets for
   * this session according to configured PDRs, FARs, QERs, URRs,
   * BARs, and MARs. Automatically detects IP vs ETH PDU type and
   * routes to correct maps.
   *
   * For each PDR:
   * - Converts all associated rules (FAR/QER/URR/BAR/MAR) to BPF structs
   * - Stores complete rule set in rules_match_pdr_map or
   *   eth_rules_match_pdr_map
   * - Populates dedicated config maps (urr_config_map, bar_config_map,
   *   mar_rules_map) and initializes runtime state maps
   * - Launches async ARP resolution for N3/N6 endpoints
   *
   * @param session PFCP session object
   *
   * @throws std::runtime_error if PDR count exceeds limits or mandatory
   *         IEs are missing
   * @see 3GPP TS 29.244 Section 5.2 - PFCP Session procedures
   */
  void CreatePipeline(std::shared_ptr<pfcp::pfcp_session> session);

  /**
   * @brief Modify existing BPF pipeline for a session
   *
   * Updates BPF maps to reflect changes in session configuration.
   * Recomputes rules_enabled flags and updates all relevant maps
   * including URR/BAR/MAR dedicated config maps.
   *
   * @param session Updated session object
   * @param teid_ul DEPRECATED - ignored (TEIDs extracted from PDRs/FARs)
   * @param teid_dl DEPRECATED - ignored (TEIDs extracted from PDRs/FARs)
   *
   * @throws std::runtime_error if PDR count exceeds limits or mandatory
   *         IEs are missing
   * @see 3GPP TS 29.244 Section 7.5.4 - PFCP Session Modification
   */
  void ModifyPipeline(
      std::shared_ptr<pfcp::pfcp_session> session, uint32_t teid_ul = 0,
      uint32_t teid_dl = 0);

  /**
   * @brief Remove BPF pipeline for a session
   * @param seid Session Endpoint Identifier
   */
  void RemovePipeline(uint64_t seid);

  // ==========================================================================
  // PFCP IE to BPF Conversion
  // Reference: 3GPP TS 29.244 Section 8.2 - Information Elements
  // ==========================================================================

  /**
   * @brief Convert PFCP FAR to BPF FAR structure
   *
   * Translates Forwarding Action Rule IE (3GPP TS 29.244 Section 8.2.3)
   * into BPF-compatible structure for data path processing.
   *
   * Key fields converted:
   * - Apply Action (3GPP TS 29.244 Section 8.2.26)
   * - Forwarding Parameters (3GPP TS 29.244 Section 8.2.74)
   * - Outer Header Creation (3GPP TS 29.244 Section 8.2.74)
   *
   * @param far PFCP FAR object (nullptr returns zeroed struct)
   * @return BPF FAR structure
   *
   * @see 3GPP TS 29.244 Section 8.2.3 - Create FAR IE
   */
  struct pfcp_far ConvertFar(std::shared_ptr<pfcp::pfcp_far> far) const;

  /**
   * @brief Convert PFCP PDR to BPF PDR structure
   *
   * Translates Packet Detection Rule IE (3GPP TS 29.244 Section 8.2.2)
   * into BPF-compatible structure for packet classification.
   *
   * Key fields converted:
   * - PDI (Packet Detection Information)
   * - Precedence (3GPP TS 29.244 Section 8.2.29)
   * - FAR ID reference
   * - QER ID reference
   * - URR ID reference
   *
   * @param pdr PFCP PDR object (nullptr returns zeroed struct)
   * @return BPF PDR structure
   *
   * @see 3GPP TS 29.244 Section 8.2.2 - Create PDR IE
   */
  struct pfcp_pdr ConvertPdr(std::shared_ptr<pfcp::pfcp_pdr> pdr) const;

  /**
   * @brief Convert PFCP QER to BPF QER structure
   *
   * Translates QoS Enforcement Rule IE (3GPP TS 29.244 Section 8.2.4)
   * into BPF-compatible structure for QoS enforcement.
   *
   * Key fields converted:
   * - Gate Status (3GPP TS 29.244 Section 8.2.25)
   * - MBR (Maximum Bitrate) (3GPP TS 29.244 Section 8.2.40)
   * - GBR (Guaranteed Bitrate) (3GPP TS 29.244 Section 8.2.41)
   * - QFI (QoS Flow Identifier) (3GPP TS 29.244 Section 8.2.89)
   *
   * @param qer PFCP QER object (nullptr returns zeroed struct)
   * @return BPF QER structure
   *
   * @see 3GPP TS 29.244 Section 8.2.4 - Create QER IE
   */
  struct pfcp_qer ConvertQer(std::shared_ptr<pfcp::pfcp_qer> qer) const;

  /**
   * @brief Convert PFCP URR to BPF URR structure
   *
   * Translates Usage Reporting Rule IE (3GPP TS 29.244 Section 8.2.5)
   * into BPF-compatible structure for usage measurement and reporting.
   *
   * Key fields converted:
   * - Reporting Triggers (3GPP TS 29.244 Section 8.2.53)
   * - Volume Threshold (3GPP TS 29.244 Section 8.2.48)
   * - Volume Quota (3GPP TS 29.244 Section 8.2.46)
   * - Measurement Period (3GPP TS 29.244 Section 8.2.72)
   * - Time Threshold (3GPP TS 29.244 Section 8.2.48)
   * - Monitoring Time (3GPP TS 29.244 Section 8.2.67)
   *
   * @param urr PFCP URR object (nullptr returns zeroed struct)
   * @return BPF URR structure
   *
   * @note Time fields are converted from seconds to nanoseconds for
   *       bpf_ktime_get_ns() comparison in the data path.
   * @see 3GPP TS 29.244 Section 8.2.5 - Create URR IE
   */
  struct pfcp_urr ConvertUrr(std::shared_ptr<pfcp::pfcp_urr> urr) const;

  /**
   * @brief Convert PFCP BAR to BPF BAR structure
   *
   * Translates Buffering Action Rule IE (3GPP TS 29.244 Section 8.2.6)
   * into BPF-compatible structure for DL buffering and DDN generation.
   *
   * Key fields converted:
   * - BAR ID (3GPP TS 29.244 Section 8.2.49)
   * - Suggested Buffering Packets Count (3GPP TS 29.244 Section 8.2.50)
   * - DL Data Notification Delay (3GPP TS 29.244 Section 8.2.28)
   *
   * BAR is referenced from FAR (via bar_id) when apply_action.buff=1,
   * not directly from PDR.
   *
   * @param bar PFCP BAR object (nullptr returns zeroed struct)
   * @return BPF BAR structure
   *
   * @see 3GPP TS 29.244 Section 8.2.6 - Create BAR IE
   * @see 3GPP TS 29.244 Section 8.2.49 - BAR ID
   */
  struct pfcp_bar ConvertBar(std::shared_ptr<pfcp::pfcp_bar> bar) const;

  /**
   * @brief Convert PFCP MAR to BPF MAR structure
   *
   * Translates Multi-Access Rule IE (3GPP TS 29.244 Section 8.2.7)
   * into BPF-compatible structure for ATSSS access steering.
   *
   * Key fields converted:
   * - MAR ID (3GPP TS 29.244 Section 8.2.74)
   * - Steering Mode (3GPP TS 29.244 Section 8.2.124)
   * - Access Forwarding Action Info 3GPP (3GPP TS 29.244 Section 8.2.75)
   * - Access Forwarding Action Info Non-3GPP (3GPP TS 29.244 Section 8.2.76)
   *
   * Steering modes: Active-Standby, Smallest-Delay, Load-Balance,
   * Priority-Based (3GPP TS 23.501 Section 5.32).
   *
   * @param mar PFCP MAR object (nullptr returns zeroed struct)
   * @return BPF MAR structure
   *
   * @see 3GPP TS 29.244 Section 8.2.7 - Create MAR IE
   * @see 3GPP TS 23.501 Section 5.32 - ATSSS
   */
  struct pfcp_mar ConvertMar(std::shared_ptr<pfcp::pfcp_mar> mar) const;

  // Rule retrieval helpers
  /**
   * @brief Retrieve URR associated with a PDR
   *
   * Follows the PDR -> URR ID -> session URR lookup chain.
   * A PDR references a URR via urr_id IE (3GPP TS 29.244 Section 8.2.44).
   *
   * @param session PFCP session containing URR definitions
   * @param pdr PDR whose URR ID to follow
   * @param[out] out_urr Populated with matching URR, or nullptr if not found
   * @return true if URR found, false otherwise
   *
   * @see 3GPP TS 29.244 Section 8.2.44 - URR ID
   */
  bool GetUrrForPdr(
      std::shared_ptr<pfcp::pfcp_session> session,
      std::shared_ptr<pfcp::pfcp_pdr> pdr,
      std::shared_ptr<pfcp::pfcp_urr>& out_urr) const;

  /**
   * @brief Retrieve BAR associated with a FAR
   *
   * Follows the FAR -> BAR ID -> session BAR lookup chain.
   * BAR is referenced from FAR (not PDR) because buffering is a
   * forwarding action property (3GPP TS 29.244 Section 8.2.49).
   *
   * @param session PFCP session containing BAR definitions
   * @param far FAR whose bar_id to follow
   * @param[out] out_bar Populated with matching BAR, or nullptr if not found
   * @return true if BAR found, false otherwise
   *
   * @see 3GPP TS 29.244 Section 8.2.49 - BAR ID
   * @see 3GPP TS 29.244 Section 8.2.26 - Apply Action (buff bit)
   */
  bool GetBarForFar(
      std::shared_ptr<pfcp::pfcp_session> session,
      std::shared_ptr<pfcp::pfcp_far> far,
      std::shared_ptr<pfcp::pfcp_bar>& out_bar) const;

  /**
   * @brief Retrieve MAR associated with a PDR
   *
   * Follows the PDR -> MAR ID -> session MAR lookup chain.
   * A PDR references a MAR via mar_id IE for ATSSS multi-access
   * steering (3GPP TS 29.244 Section 8.2.74).
   *
   * @param session PFCP session containing MAR definitions
   * @param pdr PDR whose MAR ID to follow
   * @param[out] out_mar Populated with matching MAR, or nullptr if not found
   * @return true if MAR found, false otherwise
   *
   * @note MAR is only present for ATSSS-capable sessions
   * @see 3GPP TS 29.244 Section 8.2.74 - MAR ID
   * @see 3GPP TS 23.501 Section 5.32 - ATSSS
   */
  bool GetMarForPdr(
      std::shared_ptr<pfcp::pfcp_session> session,
      std::shared_ptr<pfcp::pfcp_pdr> pdr,
      std::shared_ptr<pfcp::pfcp_mar>& out_mar) const;

  // Dedicated BPF map population (runtime state initialization)
  /**
   * @brief Populate urr_config_map and initialize urr_volume_map
   *
   * Stores the URR configuration in the BPF urr_config_map (key: SEID)
   * and initializes the volume counters in urr_volume_map to zero
   * (using BPF_NOEXIST to avoid overwriting active measurements).
   *
   * The data path (urr_apply.c) reads urr_config_map for thresholds
   * and updates urr_volume_map atomically per packet.
   *
   * @param xdp_program XDP program containing the BPF maps
   * @param seid Session Endpoint Identifier (map key)
   * @param urr_config Converted URR configuration to store
   *
   * @see 3GPP TS 29.244 Section 8.2.44-48 - URR IEs
   */
  void PopulateUrrConfigMap(
      std::shared_ptr<UPF_XDPProgram> xdp_program, uint64_t seid,
      const struct pfcp_urr& urr_config);

  /**
   * @brief Populate bar_config_map and initialize bar_state_map
   *
   * Stores the BAR configuration in the BPF bar_config_map (key: SEID)
   * and initializes the buffering state in bar_state_map to zero
   * (using BPF_NOEXIST to avoid overwriting active buffering state).
   *
   * The data path (bar_apply.c) reads bar_config_map for DDN
   * parameters and updates bar_state_map for suppression tracking.
   *
   * @param xdp_program XDP program containing the BPF maps
   * @param seid Session Endpoint Identifier (map key)
   * @param bar_config Converted BAR configuration to store
   *
   * @see 3GPP TS 29.244 Section 8.2.49-50 - BAR IEs
   * @see 3GPP TS 29.244 Section 8.2.28 - DL Data Notification Delay
   */
  void PopulateBarConfigMap(
      std::shared_ptr<UPF_XDPProgram> xdp_program, uint64_t seid,
      const struct pfcp_bar& bar_config);

  /**
   * @brief Populate mar_rules_map for a session
   *
   * Stores the MAR configuration in the BPF mar_rules_map (key: SEID).
   * The data path (mar_apply.c) reads this map to determine the
   * ATSSS steering mode and access forwarding FAR IDs.
   *
   * @param xdp_program XDP program containing the BPF maps
   * @param seid Session Endpoint Identifier (map key)
   * @param mar_rule Converted MAR configuration to store
   *
   * @see 3GPP TS 29.244 Section 8.2.74-76 - MAR IEs
   * @see 3GPP TS 23.501 Section 5.32 - ATSSS
   */
  void PopulateMarRulesMap(
      std::shared_ptr<UPF_XDPProgram> xdp_program, uint64_t seid,
      const struct pfcp_mar& mar_rule);

  // ARP Table Management
  // Reference: RFC 826 - Address Resolution Protocol
  // ==========================================================================

  /**
   * @brief Update ARP table for N6 interface (toward Data Network)
   *
   * Resolves MAC address for next-hop toward data network and updates
   * ARP table in BPF maps for fast packet forwarding.
   *
   * @param upf_xdp_program Shared pointer to UPF XDP program
   * @param dn_ip Data Network IP address
   * @param upf_n6_ip UPF N6 interface IP
   *
   * @see 3GPP TS 23.501 Section 5.8.2.3 - N6 Interface
   * @return MAC address as string (e.g., "aa:bb:cc:dd:ee:ff")
   */
  std::string UpdateArpTableForN6(
      std::shared_ptr<UPF_XDPProgram> upf_xdp_program, uint32_t dn_ip,
      uint32_t upf_n6_ip);

  /**
   * @brief Update ARP table for N3 interface (toward gNodeB)
   *
   * Resolves MAC address for next-hop toward gNodeB and updates
   * ARP table in BPF maps for fast packet forwarding.
   *
   * @param upf_xdp_program Shared pointer to UPF XDP program
   * @param gnb_ip gNodeB IP address
   * @param upf_n3_ip UPF N3 interface IP
   * @param seid Session Endpoint Identifier
   *
   * @see 3GPP TS 23.501 Section 5.8.2.2 - N3 Interface
   * @return MAC address as string (e.g., "aa:bb:cc:dd:ee:ff")
   */
  std::string UpdateArpTableForN3(
      std::shared_ptr<UPF_XDPProgram> upf_xdp_program, uint32_t gnb_ip,
      uint32_t upf_n3_ip, uint64_t seid);

  /**
   * @brief Get next-hop IP address
   *
   * Determines the next-hop IP for routing packets. If destination is on
   * same subnet, returns destination IP; otherwise returns gateway IP.
   *
   * @param local_ip Local interface IP
   * @param remote_ip Remote destination IP
   * @return Next hop IP address (gateway or direct)
   */
  uint32_t GetNextHopIp(uint32_t local_ip, uint32_t remote_ip) const;

  // ==========================================================================
  // Session Query and Management
  // ==========================================================================

  /**
   * @brief Add PFCP program to session tracking
   * @param seid Session Endpoint Identifier
   * @param xdp_program XDP program to associate with this session
   */
  void AddPfcpProgram(
      uint64_t seid, std::shared_ptr<UPF_XDPProgram> xdp_program);

  /**
   * @brief Find session programs by SEID
   * @param seid Session Endpoint Identifier
   * @return Pointer to SessionPrograms or nullptr if not found
   */
  std::shared_ptr<SessionPrograms> FindSessionPrograms(uint64_t seid) const;

  /**
   * @brief Get gNodeB IP from FAR outer header creation
   *
   * Extracts gNodeB IP address from FAR's Outer Header Creation IE
   * (3GPP TS 29.244 Section 8.2.74).
   *
   * @param far FAR containing outer header creation info
   * @return gNodeB IP address
   */
  uint32_t GetGnodebIp(std::shared_ptr<pfcp::pfcp_far> far) const;

  /**
   * @brief Retrieve gNodeB IP from session's FARs
   *
   * Scans all FARs for one with destination_interface=ACCESS and
   * Outer Header Creation, extracting the gNodeB IP address.
   *
   * @param session PFCP session to scan
   * @return gNodeB IPv4 address (network byte order), or 0 if not found
   */
  uint32_t RetrieveGnbIp(std::shared_ptr<pfcp::pfcp_session> session) const;

  /**
   * @brief Retrieve UE IP address from session's PDRs
   *
   * Scans all PDRs for one with a UE IP Address IE in its PDI.
   * Returns 0 for ETH PDU sessions (no UE IP applicable).
   *
   * @param session PFCP session to scan
   * @return UE IPv4 address (network byte order), or 0 if not found
   */
  uint32_t RetrieveUeIp(std::shared_ptr<pfcp::pfcp_session> session) const;

  /**
   * @brief Retrieve FAR associated with a PDR
   *
   * Follows the PDR -> FAR ID -> session FAR lookup chain.
   *
   * @param session PFCP session containing FAR definitions
   * @param pdr PDR whose FAR ID to follow
   * @param[out] out_far Populated with matching FAR, or nullptr if not found
   * @return true if FAR found, false otherwise
   *
   * @see 3GPP TS 29.244 Section 8.2.22 - FAR ID
   */
  bool GetFarForPdr(
      std::shared_ptr<pfcp::pfcp_session> session,
      std::shared_ptr<pfcp::pfcp_pdr> pdr,
      std::shared_ptr<pfcp::pfcp_far>& out_far) const;

  /**
   * @brief Retrieve QER associated with a PDR
   *
   * Follows the PDR -> QER ID -> session QER lookup chain.
   *
   * @param session PFCP session containing QER definitions
   * @param pdr PDR whose QER ID to follow
   * @param[out] out_qer Populated with matching QER, or nullptr if not found
   * @return true if QER found, false otherwise
   *
   * @see 3GPP TS 29.244 Section 8.2.40 - QER ID
   */
  bool GetQerForPdr(
      std::shared_ptr<pfcp::pfcp_session> session,
      std::shared_ptr<pfcp::pfcp_pdr> pdr,
      std::shared_ptr<pfcp::pfcp_qer>& out_qer) const;

  // ==========================================================================
  // Observer Pattern Support
  // ==========================================================================

  /**
   * @brief Set observer for session program state changes
   * @param observer Observer to notify of changes (usually UserPlaneComponent)
   *
   * When SessionProgramManager creates/updates/removes session programs,
   * it notifies the observer so XDP program maps can be updated.
   */
  void SetSessionObserver(ISessionObserver* observer);

  // ==========================================================================
  // Public Data (for compatibility)
  // ==========================================================================

  /// Vector of PFCP program information
  std::shared_ptr<std::vector<PfcpProgramInfo>> pfcp_programs;

 private:
  // ==========================================================================
  // Internal Methods
  // ==========================================================================

  /**
   * @brief Constructor
   * @param max_sessions Maximum number of concurrent sessions
   */
  explicit SessionProgramManager(size_t max_sessions = 1024);

  /**
   * @brief Get an empty slot in the program array
   * @return Index of empty slot, or -1 if none available
   */
  int32_t GetEmptySlot();

  // ==========================================================================
  // Member Variables
  // ==========================================================================

  /// TEID to session mapping (BPF map)
  std::shared_ptr<BpfMap> teid_session_map_;

  /// ARP table mapping (BPF map)
  std::shared_ptr<BpfMap> arp_table_map_;

  /// Observer for session program state changes (usually UserPlaneComponent)
  ISessionObserver* session_observer_;

  /// Map of SEID to SessionPrograms
  std::map<uint64_t, std::shared_ptr<SessionPrograms>> session_programs_map_;

  /// Map of SEID to QER programs for QoS enforcement
  std::map<uint64_t, std::shared_ptr<QERProgram>> qer_programs_map_;

  /// Array tracking program slots
  std::array<int64_t, 1024> program_array_;

  /// Maximum number of sessions
  size_t max_sessions_;

  /// Mutex for thread-safe access
  mutable std::mutex mutex_;

  /// ARP update tracking (per session)
  std::map<uint64_t, std::set<uint32_t>> session_n6_arp_cache_;
  std::map<uint64_t, std::set<uint32_t>> session_n3_arp_cache_;
  /// Track PDU session type per SEID for cleanup and map routing
  std::map<uint64_t, PduSessionType> session_pdu_type_map_;
};

#endif  // SESSION_PROGRAM_MANAGER_H_
