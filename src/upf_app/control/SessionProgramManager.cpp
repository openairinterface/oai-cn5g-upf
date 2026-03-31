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
 * Changes:     V17.10.0 audit — Boy Scout pass:
 *
 *   §-ref fixes throughout (same set fixed in .h — see header changelog):
 *     §8.2.3  "Create FAR" → Table 7.5.2.3-1 / §8.2.74 for FAR ID
 *     §8.2.74 for Outer Header Creation/Forwarding Parameters → TODO
 *     §8.2.74 for MAR ID → §8.2.123
 *     §8.2.75 for AFAI-3GPP → §8.2.126
 *     §8.2.76 for AFAI-Non-3GPP → §8.2.127
 *     §8.2.25 Gate Status → §8.2.7
 *     §8.2.40 MBR → §8.2.8
 *     §8.2.41 GBR → §8.2.9
 *     §8.2.11 QER ID → §8.2.75   (§8.2.11 = Precedence)
 *     §8.2.29 Precedence → §8.2.11
 *     §8.2.44 URR ID → §8.2.54
 *     §8.2.49 BAR ID → §8.2.57
 *     §8.2.50 Suggested Buffering Packets Count → §8.2.100
 *     §8.2.72 Measurement Period → TODO (§8.2.72 = Activate Predefined Rules)
 *
 *   Code fixes:
 *     - Removed 42-line commented-out dead UpdateArpTableForN6 block
 *       (lines 1985-2026 in original).  Dead code removed per boy scout rule.
 *     - Fixed variable shadowing in UpdateArpTableForN3: the inner loop
 *       declared `std::shared_ptr<UPF_XDPProgram> xdp_program` which
 *       shadowed the identically-named function parameter.  Renamed the
 *       inner variable to `slot_xdp_program`.
 *     - Added TODO comments on the three methods where the mutex is
 *       currently commented out (AddPfcpProgram, FindSessionPrograms,
 *       SetSessionObserver) — these claim thread-safety in the class
 *       Doxygen but are currently unguarded.
 *
 *   Bug fixes (functional):
 *     - ConvertBar: was reading bar->dl_buffering_suggested_packet_count for
 *       the DDN delay — that field was renamed to downlink_data_notification_delay
 *       in the pfcp_bar.hpp harmonisation.  Fixed to read the correct field.
 *     - ConvertMar: AFAI conversion only copied far_id; weight (§8.2.126),
 *       priority (§8.2.127), urr_id (§8.2.54), and rat_type (§8.2.186) were
 *       silently dropped.  Fixed for both AFAI-1 (3GPP) and AFAI-2 (Non-3GPP).
 *
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 *              3GPP TS 29.281 V17.3.0  (Release 17, 2022-09) — GTP-U
 *              3GPP TS 23.501 V17      (Release 17) — 5G System Architecture
 */
// clang-format on

/*! \file SessionProgramManager.cpp
   \brief  BPF program manager implementation for PFCP sessions.
   \author OpenAirInterface, Franck Messaoudi
   \date   2025 / 2026-03
*/

#include "SessionProgramManager.h"
#include "SessionManager.h"
#include "SessionPrograms.h"
#include "UserPlaneComponent.h"
#include "upf_xdp_limits.h"
#include <upf_xdp_user.h>
#include <qer_tc_user.h>
#include <wrappers/BPFMap.hpp>
#include <utils/compiler_hints.h>
#include <utils/endian_utils.h>
#include <helpers/NextHopFinder.hpp>
#include <helpers/SdfFilterParser.hpp>
#include <net/if.h>
#include <arpa/inet.h>
#include "observer/SessionObserver.h"
#include <errno.h>
#include <arp_types.h>
#include <pipeline_types.h>
#include <sdf_types.h>
#include "logger.hpp"
#include "upf_network_config.h"
#include "pfcp_session.hpp"
#include "pfcp_pdr.hpp"
#include "pfcp_far.hpp"
#include "pfcp_qer.hpp"
#include "pfcp_urr.hpp"
#include "pfcp_bar.hpp"
#include "pfcp_mar.hpp"
#include <pfcp_pdr.h>  // BPF PDR structure
#include <pfcp_far.h>  // BPF FAR structure
#include <pfcp_qer.h>  // BPF QER structure
#include <pfcp_urr.h>  // BPF URR structure
#include <pfcp_bar.h>  // BPF BAR structure
#include <pfcp_mar.h>  // BPF MAR structure
#include <sdf_filter.h>
#include <eth_session_id.h>
#include <rules_enabled_flags.h>

using namespace upf::utils;

static constexpr int64_t kEmptySlot = -1;

//==============================================================================
// Constructor & Destructor
//==============================================================================

SessionProgramManager::SessionProgramManager(size_t max_sessions)
    : max_sessions_(max_sessions), session_observer_(nullptr) {
  program_array_.fill(kEmptySlot);
  pfcp_programs = std::make_shared<std::vector<PfcpProgramInfo>>();
  Logger::upf_app().debug("SessionProgramManager initialized");
}

//------------------------------------------------------------------------------
SessionProgramManager::~SessionProgramManager() {
  RemoveAllSessions();
  Logger::upf_app().debug("SessionProgramManager destroyed");
}

//==============================================================================
// Singleton access
//==============================================================================

SessionProgramManager& SessionProgramManager::GetInstance() {
  static SessionProgramManager instance;
  return instance;
}

//==============================================================================
// Session lifecycle
//==============================================================================

/**
 * @brief Create a new session program slot.
 *
 * Initialises internal tracking for a new PFCP session.  The actual
 * BPF map population happens in CreatePipeline().
 *
 * @param seid  Session Endpoint Identifier (3GPP TS 29.244 V17.10.0 §8.2.37).
 */
void SessionProgramManager::CreateSession(uint64_t seid) {
  std::lock_guard<std::mutex> lock(mutex_);

  Logger::upf_app().info("Creating session " SEID_FMT, seid);
  // BPF maps are populated in CreatePipeline().
}

//------------------------------------------------------------------------------
/**
 * @brief Remove a session and clean up all BPF resources.
 *
 * Cleans up all BPF maps associated with this session:
 * - session_rules_enabled_map (tail call skip-chain flags)
 * - ETH-specific maps if Ethernet PDU session
 * - urr_config_map, urr_volume_counters_map (usage reporting state)
 * - bar_config_map, bar_state_map (buffering state)
 * - mar_rules_map (ATSSS steering)
 * - QER TC-BPF program (if instantiated)
 * - ARP caches for N3/N6 endpoints
 *
 * @param seid Session Endpoint Identifier
 *
 * @see 3GPP TS 29.244 V17.10.0 §7.5.6 — PFCP Session Deletion Request
 */
void SessionProgramManager::RemoveSession(uint64_t seid) {
  std::lock_guard<std::mutex> lock(mutex_);

  Logger::upf_app().info("Removing session " SEID_FMT, seid);

  // Remove QER program if it exists
  auto qer_it = qer_programs_map_.find(seid);
  if (qer_it != qer_programs_map_.end()) {
    Logger::upf_app().debug(
        "Tearing down QER program for seid " SEID_FMT, seid);
    qer_it->second->TearDown();
    qer_programs_map_.erase(qer_it);
  }

  // Clean up rules_enabled entry from BPF map
  auto upf_xdp_program = UserPlaneComponent::GetInstance().GetUPF_XDPProgram();
  if (upf_xdp_program) {
    auto rules_en_map =
        upf_xdp_program->GetMapByName("session_rules_enabled_map");
    if (rules_en_map) {
      rules_en_map->Remove(seid);
    }

    // Clean up ETH-specific maps if this was an ETH PDU session
    auto pdu_type_it = session_pdu_type_map_.find(seid);
    if (pdu_type_it != session_pdu_type_map_.end()) {
      if (pdu_type_it->second == PduSessionType::Ethernet) {
        Logger::upf_app().debug(
            "Cleaning up ETH PDU maps for seid " SEID_FMT, seid);
        auto eth_pdrs = upf_xdp_program->GetMapByName("eth_session_pdrs_map");
        if (eth_pdrs) eth_pdrs->Remove(seid);
      }
      session_pdu_type_map_.erase(pdu_type_it);
    }

    // Clean up URR/BAR/MAR dedicated config + runtime state maps
    auto urr_cfg_map = upf_xdp_program->GetMapByName("urr_config_map");
    if (urr_cfg_map) urr_cfg_map->Remove(seid);
    auto urr_vol_map = upf_xdp_program->GetMapByName("urr_volume_counters_map");
    if (urr_vol_map) urr_vol_map->Remove(seid);
    auto bar_cfg_map = upf_xdp_program->GetMapByName("bar_config_map");
    if (bar_cfg_map) bar_cfg_map->Remove(seid);
    auto bar_st_map = upf_xdp_program->GetMapByName("bar_state_map");
    if (bar_st_map) bar_st_map->Remove(seid);
    auto mar_map = upf_xdp_program->GetMapByName("mar_rules_map");
    if (mar_map) mar_map->Remove(seid);
  }

  // Clean up ARP caches
  session_n6_arp_cache_.erase(seid);
  session_n3_arp_cache_.erase(seid);

  // Remove from session programs map
  auto it = session_programs_map_.find(seid);
  if (it != session_programs_map_.end()) {
    session_programs_map_.erase(it);
  }

  // Remove from pfcp_programs vector
  pfcp_programs->erase(
      std::remove_if(
          pfcp_programs->begin(), pfcp_programs->end(),
          [seid](const PfcpProgramInfo& info) { return info.seid == seid; }),
      pfcp_programs->end());
}

//------------------------------------------------------------------------------
/**
 * @brief Remove all sessions and clean up all resources
 *
 * Tears down all QER programs, clears all caches and tracking maps.
 * Called during shutdown or full reset.
 */
void SessionProgramManager::RemoveAllSessions() {
  std::lock_guard<std::mutex> lock(mutex_);

  Logger::upf_app().info("Removing all sessions");

  // Remove all QER programs
  for (auto& [seid, qer_program] : qer_programs_map_) {
    Logger::upf_app().debug(
        "Tearing down QER program for seid " SEID_FMT, seid);
    qer_program->TearDown();
  }
  qer_programs_map_.clear();

  // Clear ARP caches
  session_n6_arp_cache_.clear();
  session_n3_arp_cache_.clear();

  // Clear PDU session type tracking
  session_pdu_type_map_.clear();

  // Remove session programs
  session_programs_map_.clear();
  pfcp_programs->clear();
  program_array_.fill(kEmptySlot);
}

//------------------------------------------------------------------------------
// BPF Map Management
//------------------------------------------------------------------------------

/**
 * @brief Set the TEID session map reference
 * @param map Shared pointer to BPF TEID session map
 */
void SessionProgramManager::SetTeidSessionMap(std::shared_ptr<BpfMap> map) {
  std::lock_guard<std::mutex> lock(mutex_);
  teid_session_map_ = map;
}

//------------------------------------------------------------------------------
/**
 * @brief Set the ARP table map reference
 * @param map Shared pointer to BPF ARP table map
 */
void SessionProgramManager::SetArpTableMap(std::shared_ptr<BpfMap> map) {
  std::lock_guard<std::mutex> lock(mutex_);
  arp_table_map_ = map;
}

//------------------------------------------------------------------------------
/**
 * @brief Store IP PDU session information in BPF map
 *
 * Updates the session_by_ue_ip_map with UE IP -> session_id mapping.
 * If an entry already exists for this UE IP, missing TEIDs are filled
 * in (supports split Create/Modify where UL and DL TEIDs arrive in
 * separate PFCP messages).
 *
 * @param upf_xdp_program XDP program containing the maps
 * @param ue_ip UE IP address (map key)
 * @param teid_ul Uplink TEID (3GPP TS 29.281)
 * @param teid_dl Downlink TEID (3GPP TS 29.281)
 * @param seid Session Endpoint Identifier
 *
 * @see 3GPP TS 29.281 - GTPv1-U
 */
void SessionProgramManager::StorePduSessionInMap(
    std::shared_ptr<UPF_XDPProgram> upf_xdp_program, uint32_t ue_ip,
    uint32_t teid_ul, uint32_t teid_dl, uint64_t seid) {
  if (!upf_xdp_program) {
    Logger::upf_app().error("StorePduSessionInMap: null XDP program");
    return;
  }

  try {
    // Normalize TEIDs and SEID for little-endian systems
    if (likely(IsLittleEndian())) {
      ue_ip   = htonl(ue_ip);
      teid_ul = htonl(teid_ul);
      teid_dl = htonl(teid_dl);
      // seid    = seid;     SEID stays host-endian (64-bit opaque ID)
    }

    // Perform the lookup
    // auto session_map = upf_xdp_program->GetMapByName("session_map");
    // if (session_map) {

    auto session_map = upf_xdp_program->GetSessionMappingMap();
    if (!session_map) {
      Logger::upf_app().error("session_by_ue_ip_map is null");
      return;
    }

    struct session_id session = {0};

    // Lookup session entry for UE IP
    const bool exists = (session_map->Lookup(ue_ip, &session) == 0);
    // If the session exists, update the relevant fields
    if (exists) {
      // Only fill missing TEIDs
      if (session.teid_ul == 0) {
        session.teid_ul = (teid_ul != 0 ? teid_ul : teid_dl);
      }
      if (session.teid_dl == 0) {
        session.teid_dl = (teid_dl != 0 ? teid_dl : teid_ul);
      }
      // Keep existing SEID
    } else {
      // Create new mapping entry
      session.teid_ul = teid_ul;
      session.teid_dl = teid_dl;
      session.seid    = seid;
    }

    char ue_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ue_ip, ue_ip_str, sizeof(ue_ip_str));

    // Update map
    int ret = session_map->Update(ue_ip, session, BPF_ANY);
    if (ret != 0) {
      Logger::upf_app().error(
          "Failed to update session_by_ue_ip_map for UE_IP=%s (ret=%d)",
          ue_ip_str, ret);
      return;
    }
    // Logger::upf_app().debug(
    //     "Stored PDU session: (ue_ip, seid, teid_ul, teid_dl) : (%s, "
    //     SEID_FMT
    //     ", " TEID_FMT ", " TEID_FMT ")",
    //     ue_ip_str, seid, teid_ul, teid_dl);

  } catch (const std::exception& e) {
    Logger::upf_app().error("StorePduSessionInMap failed: %s", e.what());
  }
}

//------------------------------------------------------------------------------
/**
 * @brief Store ETH PDU session information in BPF map
 *
 * Updates eth_session_mapping_map with TEID -> eth_session_id mapping.
 * Unlike IP PDU sessions (keyed by UE IP in session_by_ue_ip_map),
 * Ethernet PDU sessions are keyed by TEID since Ethernet frames
 * have no UE IP address.
 *
 * @param upf_xdp_program XDP program containing the maps
 * @param teid_ul Uplink TEID (map key, converted to network byte order)
 * @param teid_dl Downlink TEID (for GTP-U encap toward gNB)
 * @param gnb_ip gNodeB IPv4 address (for DL outer header creation)
 * @param seid Session Endpoint Identifier
 *
 * @see 3GPP TS 23.501 Section 5.6.10.3 - Ethernet PDU Session Type
 * @see 3GPP TS 29.281 - GTPv1-U
 */
void SessionProgramManager::StoreEthPduSessionInMap(
    std::shared_ptr<UPF_XDPProgram> upf_xdp_program, uint32_t teid_ul,
    uint32_t teid_dl, uint32_t gnb_ip, uint64_t seid) {
  if (!upf_xdp_program) {
    Logger::upf_app().error("StoreEthPduSessionInMap: null XDP program");
    return;
  }

  try {
    auto eth_session_map =
        upf_xdp_program->GetMapByName("eth_session_mapping_map");
    if (!eth_session_map) {
      Logger::upf_app().error(
          "eth_session_mapping_map not found - ETH PDU not supported");
      return;
    }

    uint32_t key = likely(IsLittleEndian()) ? htonl(teid_ul) : teid_ul;

    struct eth_session_id eth_session = {0};
    eth_session.teid_ul = likely(IsLittleEndian()) ? htonl(teid_ul) : teid_ul;
    eth_session.teid_dl = likely(IsLittleEndian()) ? htonl(teid_dl) : teid_dl;
    eth_session.ipv4_address = gnb_ip;
    eth_session.seid         = seid;

    int ret = eth_session_map->Update(key, eth_session, BPF_ANY);
    if (ret != 0) {
      Logger::upf_app().error(
          "Failed to update eth_session_mapping_map TEID=0x%x (ret=%d)",
          teid_ul, ret);
      return;
    }

    Logger::upf_app().debug(
        "Stored ETH PDU session: TEID_UL=0x%x TEID_DL=0x%x SEID=" SEID_FMT,
        teid_ul, teid_dl, seid);
  } catch (const std::exception& e) {
    Logger::upf_app().error("StoreEthPduSessionInMap failed: %s", e.what());
  }
}

//------------------------------------------------------------------------------
// Tail Call Rule Enable Flags
//------------------------------------------------------------------------------

/**
 * @brief Compute rules_enabled bitmask from session content
 *
 * Examines the PFCP session's PDRs and FARs to determine which
 * downstream tail call programs should be active for this session:
 *   - QER referenced by any PDR -> RULE_QER_ENABLED
 *   - URR referenced by any PDR -> RULE_URR_ENABLED
 *   - BAR associated with any FAR -> RULE_BAR_ENABLED
 *   - MAR referenced by any PDR -> RULE_MAR_ENABLED
 *
 * The bitmask is stored in session_rules_enabled_map and cached in
 * pctx->rules_enabled by the session lookup BPF program, enabling
 * the tail call skip-chain to bypass disabled programs at zero cost.
 *
 * @param session PFCP session to analyze
 * @return Bitmask of RULE_*_ENABLED flags
 *
 * @see rules_enabled_flags.h for flag definitions
 * @see tail_call_dispatch.h for skip-chain implementation
 * @see 3GPP TS 29.244 Section 7.2.2 - PFCP Session Establishment
 */
uint32_t SessionProgramManager::ComputeRulesEnabledFlags(
    std::shared_ptr<pfcp::pfcp_session> session) const {
  uint32_t flags = 0;
  if (!session) return flags;

  for (const auto& pdr : session->pdrs) {
    pfcp::qer_id_t qer_id;
    if (pdr->get(qer_id)) {
      flags |= RULE_QER_ENABLED;
      break;
    }
  }
  for (const auto& pdr : session->pdrs) {
    pfcp::urr_id_t urr_id;
    if (pdr->get(urr_id)) {
      flags |= RULE_URR_ENABLED;
      break;
    }
  }
  for (const auto& far : session->fars) {
    if (far->bar_id.first) {
      flags |= RULE_BAR_ENABLED;
      break;
    }
  }
  // MAR: ATSSS multi-access steering (TS 23.501 Section 5.32)
  for (const auto& pdr : session->pdrs) {
    pfcp::mar_id_t mar_id;
    if (pdr->get(mar_id)) {
      flags |= RULE_MAR_ENABLED;
      break;
    }
  }
  return flags;
}

//------------------------------------------------------------------------------
/**
 * @brief Update session_rules_enabled_map in BPF
 *
 * Stores the computed rules_enabled bitmask so the tail call
 * skip-chain dispatch can bypass disabled programs at zero cost
 * (no tail call for disabled rule types).
 *
 * Replaces the old session_qos_enabled_map which only tracked QER.
 *
 * @param upf_xdp_program XDP program containing the map
 * @param seid Session Endpoint Identifier (map key)
 * @param flags Bitmask of RULE_*_ENABLED flags (map value)
 *
 * @see rules_enabled_flags.h for flag definitions
 * @see tail_call_dispatch.h for skip-chain implementation
 */
void SessionProgramManager::UpdateRulesEnabledMap(
    std::shared_ptr<UPF_XDPProgram> upf_xdp_program, uint64_t seid,
    uint32_t flags) {
  if (!upf_xdp_program) return;

  auto rules_map = upf_xdp_program->GetMapByName("session_rules_enabled_map");
  if (!rules_map) {
    Logger::upf_app().warn(
        "session_rules_enabled_map not found - skip-chain will not optimize");
    return;
  }

  int ret = rules_map->Update(seid, flags, BPF_ANY);
  if (ret != 0) {
    Logger::upf_app().error(
        "Failed to update session_rules_enabled_map SEID=" SEID_FMT " (ret=%d)",
        seid, ret);
    return;
  }

  Logger::upf_app().debug(
      "Rules enabled SEID=" SEID_FMT ": 0x%x [QER=%s URR=%s BAR=%s MAR=%s]",
      seid, flags, (flags & RULE_QER_ENABLED) ? "ON" : "off",
      (flags & RULE_URR_ENABLED) ? "ON" : "off",
      (flags & RULE_BAR_ENABLED) ? "ON" : "off",
      (flags & RULE_MAR_ENABLED) ? "ON" : "off");
}

//------------------------------------------------------------------------------
// PDU Session Type Detection
//------------------------------------------------------------------------------

/**
 * @brief Detect whether a PFCP session is IP or Ethernet PDU type
 *
 * Determines BPF map routing based on PDU session type:
 * - IP PDU: session_by_ue_ip_map, pdrs_per_session_map, rules_match_pdr_map
 * - ETH PDU: eth_session_mapping_map, eth_session_pdrs_map,
 *            eth_rules_match_pdr_map
 *
 * Detection heuristic:
 *   1. If any PDR contains a UE IP Address IE -> IP PDU
 *   2. If no PDR has UE IP (all use F-TEID only) -> Ethernet PDU
 *
 * @param session PFCP session to check
 * @return PduSessionType::Ethernet or PduSessionType::IP
 *
 * @note Future improvement: use explicit PDU Session Type IE from PFCP
 *       Session Establishment Request (3GPP TS 29.244 Section 8.2.124)
 * @see 3GPP TS 23.501 Section 5.6.10.3 - Ethernet PDU Session Type
 */
PduSessionType SessionProgramManager::DetectPduSessionType(
    std::shared_ptr<pfcp::pfcp_session> session) const {
  if (!session) return PduSessionType::IP;

  // Heuristic: no UE IP in any PDR -> ETH PDU session (TS 23.501
  // Section 5.6.10.3)
  for (const auto& pdr : session->pdrs) {
    pfcp::pdi pdi;
    pfcp::ue_ip_address_t ue_ip;
    if (pdr->get(pdi) && pdi.get(ue_ip)) {
      if (ue_ip.ipv4_address.s_addr != 0) {
        return PduSessionType::IP;
      }
    }
  }

  if (!session->pdrs.empty()) {
    Logger::upf_app().info(
        "Session " SEID_FMT " detected as Ethernet PDU (no UE IP in any PDR)",
        session->get_up_seid());
    return PduSessionType::Ethernet;
  }

  return PduSessionType::IP;
}

//------------------------------------------------------------------------------
// Pipeline Management - 3GPP TS 29.244 Section 5.2
//------------------------------------------------------------------------------
/**
 * @brief Create BPF pipeline for a new PFCP session
 *
 * Processes all PDRs in the session and configures BPF maps for packet
 * processing. For each PDR this includes:
 * - Validating PDR count against system limits
 * - Extracting PDI (Packet Detection Information) from each PDR
 * - Converting all associated rules to BPF structures:
 *   - FAR (Forwarding Action Rules, Section 8.2.3)
 *   - QER (QoS Enforcement Rules, Section 8.2.4)
 *   - URR (Usage Reporting Rules, Section 8.2.5)
 *   - BAR (Buffering Action Rules, Section 8.2.6, via FAR -> bar_id)
 *   - MAR (Multi-Access Rules, Section 8.2.7, ATSSS only)
 * - Storing complete rule set in rules_match_pdr_map (IP PDU) or
 *   eth_rules_match_pdr_map (ETH PDU)
 * - Populating dedicated config maps (urr_config_map, bar_config_map,
 *   mar_rules_map) and initializing runtime state (urr_volume_counters_map,
 *   bar_state_map) with BPF_NOEXIST to avoid overwriting active state
 * - Computing and storing rules_enabled flags for tail call skip-chain
 * - Detecting IP vs ETH PDU type and routing to correct BPF maps
 * - Launching async ARP table updates for N3/N6 interfaces
 *
 * @param session PFCP session containing PDRs, FARs, QERs, URRs, BARs, MARs
 * @throws std::runtime_error if PDR count exceeds MAX_PDRS_SESSION or
 *         mandatory IEs are missing
 *
 * 3GPP References:
 * - TS 29.244 Section 7.2.2: PFCP Session Establishment
 * - TS 23.501 Section 5.8: User Plane function
 * - TS 23.501 Section 5.6.10.3: Ethernet PDU Session Type
 */

void SessionProgramManager::CreatePipeline(
    std::shared_ptr<pfcp::pfcp_session> session) {
  if (!session) {
    Logger::upf_app().error(
        "[eBPF] Create Pipeline: Invalid session pointer (null)");
    return;
  }

  const uint64_t seid = session->get_up_seid();
  auto& logger        = Logger::upf_app();

  logger.info(
      "[eBPF] Create Pipeline - Creating pipeline for session " SEID_FMT, seid);

  try {
    // Validate PDR count against system limits

    if (session->pdrs.size() > MAX_PDRS_PER_PDU_SESSION_LIMIT) {
      logger.error(
          "[eBPF] Create Pipeline - Session " SEID_FMT
          " has %zu PDRs, exceeds limit of %d",
          seid, session->pdrs.size(), MAX_PDRS_PER_PDU_SESSION_LIMIT);
      throw std::runtime_error(
          "Number of requested PDRs exceeds the allocated size for PDRs "
          "vector");
    }

    // Get BPF program handle
    auto upf_xdp_program =
        UserPlaneComponent::GetInstance().GetUPF_XDPProgram();
    if (!upf_xdp_program) {
      logger.error("[eBPF] Create Pipeline - XDP program not available");
      throw std::runtime_error("UPF XDP program not available");
    }

    // Detect PDU session type (IP vs Ethernet)
    PduSessionType pdu_type     = DetectPduSessionType(session);
    const bool is_eth_pdu       = (pdu_type == PduSessionType::Ethernet);
    session_pdu_type_map_[seid] = pdu_type;

    if (is_eth_pdu) {
      logger.info("[eBPF] Create Pipeline - ETH PDU session " SEID_FMT, seid);
    }

    // Initialize PDR array for BPF map
    struct pfcp_pdr pdrs[MAX_PDRS_PER_PDU_SESSION_LIMIT] = {0};
    int pdr_index                                        = 0;

    // ETH PDU session variables populated inside the PDR loop,
    // used after it to call StoreEthPduSessionInMap with both TEIDs.
    uint32_t eth_ul_teid = 0;
    uint32_t eth_dl_teid = 0;
    uint32_t eth_gnb_ip  = 0;

    // Get network configuration for ARP updates
    const uint32_t dn_ip     = upf::GetDnIp();
    const uint32_t upf_n3_ip = upf::GetN3Ip();
    const uint32_t upf_n6_ip = upf::GetN6Ip();

    pfcp::pdi pdi;
    pfcp::fteid_t fteid;
    pfcp::ue_ip_address_t ue_ip_address;
    pfcp::source_interface_t source_interface;
    uint16_t pdr_id;

    // Get or create the sets for this session
    auto& n6_ips_updated = session_n6_arp_cache_[seid];
    auto& n3_ips_updated = session_n3_arp_cache_[seid];

    // Process each PDR in the session
    for (const auto& pdr : session->pdrs) {
      pdr_id = pdr->pdr_id.rule_id;
      logger.debug(
          "[eBPF] Create Pipeline: seid 0x%lx - Starting PDR rule %u "
          "establishment",
          seid, pdr_id);

      // Extract PDI (Packet Detection Information) - mandatory
      if (!(pdr->get(pdi) && pdi.get(source_interface))) {
        throw std::runtime_error(
            "Missing mandatory IE (PDI or Source Interface) in PDR " +
            std::to_string(pdr_id));
      }

      // Extract F-TEID (Fully Qualified TEID)
      if (!pdi.get(fteid)) {
        fteid.teid = 0;
        logger.warn(
            "F-TEID missing for PDR %u (CH bit: %s)", pdr_id,
            fteid.ch ? "Set" : "Not Set");
        // TODO: Implement logic for CHOOSE mode (CH bit set)
      }

      // Extract UE IP address
      if (!pdi.get(ue_ip_address)) {
        ue_ip_address.ipv4_address.s_addr = 0;
        if (!is_eth_pdu) {
          logger.warn("UE IP address missing for PDR %u", pdr_id);
        }
        // TODO: Implement IP allocation when UE IP is not provided
      }

      // Store session mapping (IP or ETH PDU)
      if (is_eth_pdu) {
        StoreEthPduSessionInMap(upf_xdp_program, fteid.teid, 0, 0, seid);
      } else {
        StorePduSessionInMap(
            upf_xdp_program, ue_ip_address.ipv4_address.s_addr, fteid.teid, 0,
            seid);
      }

      // Retrieve associated FAR
      std::shared_ptr<pfcp::pfcp_far> far;
      if (!GetFarForPdr(session, pdr, far)) {
        throw std::runtime_error(
            "FAR not found for PDR " + std::to_string(pdr_id));
      }

      // For ETH PDU downlink PDRs: extract DL TEID and gNB IP from FAR
      if (is_eth_pdu &&
          source_interface.interface_value == INTERFACE_VALUE_CORE) {
        eth_dl_teid = SessionManager::GetDownlinkTeidFromFar(far);
        eth_gnb_ip  = GetGnodebIp(far);
      }
      // For ETH PDU uplink PDRs: capture UL TEID (gNB→UPF)
      if (is_eth_pdu &&
          source_interface.interface_value == INTERFACE_VALUE_ACCESS) {
        eth_ul_teid = fteid.teid;
      }

      // Retrieve associated QER (optional)
      std::shared_ptr<pfcp::pfcp_qer> qer = nullptr;
      if (!GetQerForPdr(session, pdr, qer)) {
        logger.debug("No QER associated with PDR %u", pdr_id);
      }

      // Retrieve and convert URR (optional, TS 29.244 Section 8.2.44)
      std::shared_ptr<pfcp::pfcp_urr> urr = nullptr;
      GetUrrForPdr(session, pdr, urr);

      // Retrieve and convert BAR (optional, via FAR, TS 29.244 Section 8.2.49)
      std::shared_ptr<pfcp::pfcp_bar> bar = nullptr;
      GetBarForFar(session, far, bar);

      // Retrieve and convert MAR (optional, TS 29.244 Section 8.2.74)
      std::shared_ptr<pfcp::pfcp_mar> mar = nullptr;
      GetMarForPdr(session, pdr, mar);

      // Convert PFCP IEs to BPF structures (TS 29.244 Section 8.2)
      struct pfcp_pdr bpf_pdr = ConvertPdr(pdr);
      struct pfcp_far bpf_far = ConvertFar(far);
      struct pfcp_qer bpf_qer = ConvertQer(qer);
      struct pfcp_urr bpf_urr = ConvertUrr(urr);
      struct pfcp_bar bpf_bar = ConvertBar(bar);
      struct pfcp_mar bpf_mar = ConvertMar(mar);

      // For downlink PDRs, QFI is not in PDI (no incoming GTP-U
      // header) Copy QFI from QER into PDR's PDI for BPF matching logic See
      // 3GPP TS 29.244 Section 8.2.89 - QFI is in QER for downlink
      if (bpf_pdr.pdi.qfi.qfi == 0 && bpf_qer.qos_flow_identifier.qfi != 0) {
        bpf_pdr.pdi.qfi.qfi = bpf_qer.qos_flow_identifier.qfi;
      }

      /* Update rules_match_pdr map with ALL rules (TS 29.244 Section 8.2)
       * (PDR ID + SEID -> FAR + QER + URR + BAR + MAR)
       */
      struct rules_match_pdr rules = {0};
      rules.far                    = bpf_far;
      rules.qer                    = bpf_qer;
      rules.urr                    = bpf_urr;
      rules.bar                    = bpf_bar;
      rules.mar                    = bpf_mar;

      // Populate dedicated config maps for URR/BAR/MAR (runtime state init)
     /* if (bpf_urr.urr_id != 0) {
        PopulateUrrConfigMap(upf_xdp_program, seid, bpf_urr);
      }
      if (bpf_bar.bar_id != 0) {
        PopulateBarConfigMap(upf_xdp_program, seid, bpf_bar);
      }
      if (bpf_mar.mar_id != 0) {
        PopulateMarRulesMap(upf_xdp_program, seid, bpf_mar);
      }
*/
      struct pdrs_per_session pdr_key = {0};
      pdr_key.pdr_id                  = pdr_id;
      pdr_key.seid                    = seid;

      const char* rules_map_name =
          is_eth_pdu ? "eth_rules_match_pdr_map" : "rules_match_pdr_map";
      auto rules_map = upf_xdp_program->GetMapByName(rules_map_name);
      if (rules_map) {
        rules_map->Update(pdr_key, rules, BPF_ANY);
      }

      // Launch async ARP table updates based on source interface
      if (source_interface.interface_value == INTERFACE_VALUE_ACCESS) {
        // Uplink PDR - update N6 ARP (toward Data Network)
        if ((dn_ip > 0) &&
            (n6_ips_updated.find(dn_ip) == n6_ips_updated.end())) {
          n6_ips_updated.insert(dn_ip);  // Mark as updated

          std::thread update_arp_n6(
              [this, upf_xdp_program, dn_ip, upf_n6_ip, pdr_id, seid]() {
                try {
                  char buf_dn_ip[INET_ADDRSTRLEN];
                  struct in_addr addr_dn_ip = {.s_addr = dn_ip};
                  inet_ntop(AF_INET, &addr_dn_ip, buf_dn_ip, INET_ADDRSTRLEN);

                  std::string mac =
                      UpdateArpTableForN6(upf_xdp_program, dn_ip, upf_n6_ip);
                  Logger::upf_app().debug(
                      "ARP: %s dev %s lladdr %s [SEID=%" PRIu64 "]", buf_dn_ip,
                      upf::GetN6Iface().c_str(), mac.c_str(), seid);
                } catch (const std::exception& ex) {
                  Logger::upf_app().error(
                      "N6 ARP update failed for PDR %u: %s", pdr_id, ex.what());
                }
              });
          update_arp_n6.detach();
        }
      } else if (source_interface.interface_value == INTERFACE_VALUE_CORE) {
        // Downlink PDR - update N3 ARP (toward gNodeB)
        uint32_t gnb_ip = RetrieveGnbIp(session);
        if ((gnb_ip > 0) &&
            (n3_ips_updated.find(gnb_ip) == n3_ips_updated.end())) {
          n3_ips_updated.insert(gnb_ip);  // Mark as updated

          std::thread update_arp_n3([this, upf_xdp_program, gnb_ip, upf_n3_ip,
                                     pdr_id, seid]() {
            try {
              char buf_gnb_ip[INET_ADDRSTRLEN];
              struct in_addr addr_gnb_ip = {.s_addr = gnb_ip};
              inet_ntop(AF_INET, &addr_gnb_ip, buf_gnb_ip, INET_ADDRSTRLEN);

              std::string mac =
                  UpdateArpTableForN3(upf_xdp_program, gnb_ip, upf_n3_ip, seid);
              Logger::upf_app().debug(
                  "ARP: %s dev %s lladdr %s [SEID=%" PRIu64 "]", buf_gnb_ip,
                  upf::GetN3Iface().c_str(), mac.c_str(), seid);
            } catch (const std::exception& ex) {
              Logger::upf_app().error(
                  "N3 ARP update failed for PDR %u: %s", pdr_id, ex.what());
            }
          });
          update_arp_n3.detach();
        }
      }
      // Store PDR in array for batch update
      pdrs[pdr_index] = bpf_pdr;
      pdr_index++;
    }

    // For ETH PDU: now that we have both UL TEID (from uplink PDR) and
    // DL TEID + gNB IP (from downlink FAR), populate the session map once.
    // (TS 23.501 Section 5.6.10.3 - ETH sessions keyed by TEID, not UE IP)
    if (is_eth_pdu && eth_ul_teid != 0) {
      StoreEthPduSessionInMap(
          upf_xdp_program, eth_ul_teid, eth_dl_teid, eth_gnb_ip, seid);
    }

    // Store all PDRs in correct session PDR map
    const char* pdrs_map_name =
        is_eth_pdu ? "eth_session_pdrs_map" : "pdrs_per_session_map";
    auto session_pdrs_map = upf_xdp_program->GetMapByName(pdrs_map_name);
    if (session_pdrs_map) {
      session_pdrs_map->Update(seid, pdrs, BPF_ANY);
    }

    // Compute and store rules_enabled flags for tail call skip-chain
    uint32_t rules_flags = ComputeRulesEnabledFlags(session);
    UpdateRulesEnabledMap(upf_xdp_program, seid, rules_flags);

    logger.info(
        "Pipeline created for session " SEID_FMT
        " with %d PDRs "
        "[type = %s, rules = 0x%x]",
        seid, pdr_index, is_eth_pdu ? "ETH" : "IP", rules_flags);

  } catch (const std::exception& e) {
    logger.error(
        "CreatePipeline failed for session " SEID_FMT ": %s", seid, e.what());
    throw;
  }
}

//------------------------------------------------------------------------------
// Pipeline Modification - 3GPP TS 29.244 Section 7.5.4
//------------------------------------------------------------------------------
/**
 * @brief Modify BPF pipeline for an existing PFCP session
 *
 * Updates BPF maps to reflect session modifications. For each PDR:
 * - Validating PDR count against system limits
 * - Detecting IP vs ETH PDU type for correct map routing
 * - Updating PDU session mapping:
 *   - IP PDU: session_by_ue_ip_map (UE IP keyed)
 *   - ETH PDU: eth_session_mapping_map (TEID keyed)
 * - Re-converting all rules (FAR/QER/URR/BAR/MAR) to BPF structures
 * - Updating BPF maps: session_pdrs, rules_match_pdr, sdf_filters
 * - Repopulating dedicated config maps (urr_config_map, bar_config_map,
 *   mar_rules_map) and initializing runtime state with BPF_NOEXIST
 * - Recomputing rules_enabled flags for tail call skip-chain
 * - Launching async ARP table updates for modified endpoints
 *
 * @param session PFCP session with updated PDRs, FARs, QERs, URRs, BARs, MARs
 * @param teid_ul DEPRECATED - not used (TEIDs extracted from PDRs/FARs)
 * @param teid_dl DEPRECATED - not used (TEIDs extracted from PDRs/FARs)
 * @throws std::runtime_error if PDR count exceeds limits, mandatory IEs
 * missing, or UE/gNB IP addresses not found (UE IP skipped for ETH PDU)
 *
 * 3GPP References:
 * - TS 29.244 Section 7.5.4: PFCP Session Modification
 * - TS 29.244 Section 8.2.9-11: Update PDR/FAR/QER
 * - TS 29.244 Section 8.2.44-76: Update URR/BAR/MAR
 *
 * NOTE: TEIDs are now extracted from individual PDRs/FARs, not passed as
 * parameters
 */
void SessionProgramManager::ModifyPipeline(
    std::shared_ptr<pfcp::pfcp_session> session,
    uint32_t teid_ul,    // DEPRECATED - ignored
    uint32_t teid_dl) {  // DEPRECATED - ignored

  if (!session) {
    Logger::upf_app().error("ModifyPipeline: null session");
    return;
  }

  const uint64_t seid = session->get_up_seid();
  auto& logger        = Logger::upf_app();

  logger.info(
      "[eBPF] Modify Pipeline - Updating pipeline for session " SEID_FMT, seid);

  try {
    // Validate PDR count against system limits
    if (session->pdrs.size() > MAX_PDRS_PER_PDU_SESSION_LIMIT) {
      logger.error(
          "Session " SEID_FMT " has %zu PDRs, exceeds limit of %d", seid,
          session->pdrs.size(), MAX_PDRS_PER_PDU_SESSION_LIMIT);
      throw std::runtime_error(
          "Number of requested PDRs exceeds the allocated size for PDRs "
          "vector");
    }

    // Get BPF program handle
    auto upf_xdp_program =
        UserPlaneComponent::GetInstance().GetUPF_XDPProgram();
    if (!upf_xdp_program) {
      throw std::runtime_error("UPF XDP program not available");
    }

    // Initialize PDR array for BPF map
    struct pfcp_pdr pdrs[MAX_PDRS_PER_PDU_SESSION_LIMIT] = {0};
    int pdr_index                                        = 0;

    // Detect PDU session type (IP vs Ethernet)
    PduSessionType pdu_type     = DetectPduSessionType(session);
    const bool is_eth_pdu       = (pdu_type == PduSessionType::Ethernet);
    session_pdu_type_map_[seid] = pdu_type;

    // Get network configuration for ARP updates
    const uint32_t dn_ip     = upf::GetDnIp();
    const uint32_t upf_n3_ip = upf::GetN3Ip();
    const uint32_t upf_n6_ip = upf::GetN6Ip();

    // Get or create the sets for this session
    auto& n6_ips_updated = session_n6_arp_cache_[seid];
    auto& n3_ips_updated = session_n3_arp_cache_[seid];

    // Retrieve UE and gNB IPs
    // UE IP is mandatory for IP PDU sessions but not for ETH PDU sessions
    // (TS 23.501 Section 5.6.10.3 - ETH PDU sessions keyed by TEID not UE IP)
    uint32_t ue_ip = RetrieveUeIp(session);
    if (!ue_ip && !is_eth_pdu) {
      logger.warn(
          "Missing UE IP for IP PDU session " SEID_FMT
          " — session mapping may be incomplete",
          seid);
      // Don't throw: allow partial modifications (e.g. FAR-only updates)
    }

    uint32_t gnb_ip = RetrieveGnbIp(session);
    if (!gnb_ip) {
      logger.warn(
          "Missing gNB IP for session " SEID_FMT
          " — N3 ARP will not be updated",
          seid);
    }

    // Compute and store rules_enabled flags for tail call skip-chain
    // Replaces old session_qos_enabled_map with unified bitmask
    uint32_t rules_flags = ComputeRulesEnabledFlags(session);
    UpdateRulesEnabledMap(upf_xdp_program, seid, rules_flags);

    // ── Per-session stage program Setup() calls ─────────────────────────────
    // rules_flags was computed and written to session_rules_enabled_map above.
    // Use it here (no redundant IsQosEnabled() / IsBpfDatapathEnabled() calls)
    // to decide which per-session maps and TC programs need to be initialised.
    // This mirrors the pipeline-level Setup() in UPF_XDPProgram which only
    // loads the XDP programs; per-session map population is done here.
    // ─────────────────────────────────────────────────────────────────────────

    // QER-XDP: gate-check is stateless -- rules_match_pdr_map already carries
    // the pfcp_qer struct per PDR; no per-session map write needed here.

    // QER-TC: per-session HTB class setup (rate shaping via TC BPF).
    // Requires downlink QER rules and RULE_QER_ENABLED in rules_flags.
    if ((rules_flags & RULE_QER_ENABLED) && !session->qers_downlink.empty()) {
      logger.debug("Setup QERTCProgram for SEID=" SEID_FMT, seid);
      std::shared_ptr<QERTCProgram> qer_program =
          std::make_shared<QERTCProgram>();
      qer_program->Setup(seid, session->qers_downlink, session->pdrs_downlink);
      {
        std::lock_guard<std::mutex> lock(mutex_);
        qer_programs_map_[seid] = qer_program;
      }
    }

    // URR: populate urr_config_map + initialise urr_volume_counters_map.
    if ((rules_flags & RULE_URR_ENABLED) && !session->urrs.empty()) {
      auto urr = upf_xdp_program->GetUrrProgram();
      if (urr) {
        logger.debug("Setup URRProgram for SEID=" SEID_FMT, seid);
        urr->Setup(seid, session->urrs);
      }
    }

    // BAR: populate bar_config_map + initialise bar_state_map.
    if ((rules_flags & RULE_BAR_ENABLED) && !session->bars.empty()) {
      auto bar = upf_xdp_program->GetBarProgram();
      if (bar) {
        logger.debug("Setup BARProgram for SEID=" SEID_FMT, seid);
        bar->Setup(seid, session->bars);
      }
    }

    // MAR: populate mar_config_map + initialise mar_access_state_map.
    if ((rules_flags & RULE_MAR_ENABLED) && !session->mars.empty()) {
      auto mar = upf_xdp_program->GetMarProgram();
      if (mar) {
        logger.debug("Setup MARProgram for SEID=" SEID_FMT, seid);
        mar->Setup(seid, session->mars);
      }
    }

    // Extract TEIDs from uplink PDRs
    std::vector<uint32_t> uplink_teids;
    for (const auto& pdr : session->pdrs_uplink) {
      uint32_t teid = SessionManager::GetUplinkTeidFromPdr(pdr);
      if (teid != 0) {
        uplink_teids.push_back(teid);
      }
    }

    // Extract TEIDs from downlink FARs
    std::vector<uint32_t> downlink_teids;
    for (const auto& pdr : session->pdrs_downlink) {
      std::shared_ptr<pfcp::pfcp_far> far;
      if (GetFarForPdr(session, pdr, far)) {
        uint32_t teid = SessionManager::GetDownlinkTeidFromFar(far);
        if (teid != 0) {
          downlink_teids.push_back(teid);
        }
      }
    }

    // Update PDU session mapping for each TEID
    // Note: If your BPF map supports only one TEID per session, you'll need to
    // pick the primary TEID or update your BPF map structure
    if (!uplink_teids.empty() || !downlink_teids.empty()) {
      // Use first TEID of each direction for PDU session mapping
      // (This maintains backward compatibility with single-TEID maps)
      uint32_t primary_teid_ul = uplink_teids.empty() ? 0 : uplink_teids[0];
      uint32_t primary_teid_dl = downlink_teids.empty() ? 0 : downlink_teids[0];

      if (is_eth_pdu) {
        // ETH PDU: TEID-keyed mapping with gNB IP for DL encap
        StoreEthPduSessionInMap(
            upf_xdp_program, primary_teid_ul, primary_teid_dl, gnb_ip, seid);
      } else {
        // IP PDU: UE IP-keyed mapping
        StorePduSessionInMap(
            upf_xdp_program, ue_ip, primary_teid_ul, primary_teid_dl, seid);
      }

      // Log if there are multiple TEIDs (warning about BPF map limitation)
      if (uplink_teids.size() > 1) {
        logger.warn(
            "Session " SEID_FMT
            " has %zu uplink TEIDs, but PDU session map "
            "stores only primary TEID " TEID_FMT,
            seid, uplink_teids.size(), primary_teid_ul);
      }
      if (downlink_teids.size() > 1) {
        logger.warn(
            "Session " SEID_FMT
            " has %zu downlink TEIDs, but PDU session map "
            "stores only primary TEID " TEID_FMT,
            seid, downlink_teids.size(), primary_teid_dl);
      }
    } else {
      logger.warn(
          "Session " SEID_FMT " has no TEIDs - PDU session mapping not updated",
          seid);
    }

    // Process each PDR in the session
    pfcp::pdi pdi;
    pfcp::source_interface_t source_interface;
    uint16_t pdr_id = 0;

    for (const auto& pdr : session->pdrs) {
      pdr_id = pdr->pdr_id.rule_id;

      // Extract PDI (Packet Detection Information)
      bool has_pdi = pdr->get(pdi) && pdi.get(source_interface);
      if (!has_pdi) {
        logger.warn(
            "Missing PDI or Source Interface for PDR %u, skipping ARP update",
            pdr_id);
        // Continue processing - PDI might not be updated in modification
      }

      // Retrieve associated FAR
      std::shared_ptr<pfcp::pfcp_far> far;
      if (!GetFarForPdr(session, pdr, far)) {
        throw std::runtime_error(
            "FAR not found for PDR " + std::to_string(pdr_id));
      }

      // Retrieve associated QER (optional)
      std::shared_ptr<pfcp::pfcp_qer> qer = nullptr;
      if (!GetQerForPdr(session, pdr, qer)) {
        logger.debug("No QER associated with PDR %u", pdr_id);
      }

      // Retrieve URR (optional, TS 29.244 Section 8.2.44)
      std::shared_ptr<pfcp::pfcp_urr> urr = nullptr;
      GetUrrForPdr(session, pdr, urr);

      // Retrieve BAR (optional, via FAR, TS 29.244 Section 8.2.49)
      std::shared_ptr<pfcp::pfcp_bar> bar = nullptr;
      GetBarForFar(session, far, bar);

      // Retrieve MAR (optional, TS 29.244 Section 8.2.74)
      std::shared_ptr<pfcp::pfcp_mar> mar = nullptr;
      GetMarForPdr(session, pdr, mar);

      // Convert PFCP IEs to BPF structures (TS 29.244 Section 8.2)
      struct pfcp_pdr bpf_pdr = ConvertPdr(pdr);
      struct pfcp_far bpf_far = ConvertFar(far);
      struct pfcp_qer bpf_qer = ConvertQer(qer);
      struct pfcp_urr bpf_urr = ConvertUrr(urr);
      struct pfcp_bar bpf_bar = ConvertBar(bar);
      struct pfcp_mar bpf_mar = ConvertMar(mar);

      // CRITICAL: For downlink PDRs, QFI is not in PDI (no incoming GTP-U
      // header) Copy QFI from QER into PDR's PDI for BPF matching logic See
      // 3GPP TS 29.244 Section 8.2.89 - QFI is in QER for downlink
      if (bpf_pdr.pdi.qfi.qfi == 0 && bpf_qer.qos_flow_identifier.qfi != 0) {
        bpf_pdr.pdi.qfi.qfi = bpf_qer.qos_flow_identifier.qfi;
      }

      /* Update rules_match_pdr map with ALL rules (TS 29.244 Section 8.2)
       * (PDR ID + SEID -> FAR + QER + URR + BAR + MAR)
       */
      struct rules_match_pdr rules = {0};
      rules.far                    = bpf_far;
      rules.qer                    = bpf_qer;
      rules.urr                    = bpf_urr;
      rules.bar                    = bpf_bar;
      rules.mar                    = bpf_mar;

      // Populate dedicated config maps for URR/BAR/MAR (runtime state init)
     /* if (bpf_urr.urr_id != 0) {
        PopulateUrrConfigMap(upf_xdp_program, seid, bpf_urr);
      }
      if (bpf_bar.bar_id != 0) {
        PopulateBarConfigMap(upf_xdp_program, seid, bpf_bar);
      }
      if (bpf_mar.mar_id != 0) {
        PopulateMarRulesMap(upf_xdp_program, seid, bpf_mar);
      }
*/
      struct pdrs_per_session pdr_key = {0};
      pdr_key.pdr_id                  = pdr_id;
      pdr_key.seid                    = seid;

      // Use correct rules_match_pdr map based on session type
      const char* rules_map_name =
          is_eth_pdu ? "eth_rules_match_pdr_map" : "rules_match_pdr_map";
      auto rules_map = upf_xdp_program->GetMapByName(rules_map_name);
      if (rules_map) {
        rules_map->Update(pdr_key, rules, BPF_ANY);
      }

      // Launch async ARP table updates based on source interface
      if (has_pdi) {
        if (source_interface.interface_value == INTERFACE_VALUE_ACCESS) {
          // Uplink PDR - update N6 ARP (toward Data Network)
          if ((dn_ip > 0) &&
              (n6_ips_updated.find(dn_ip) == n6_ips_updated.end())) {
            n6_ips_updated.insert(dn_ip);  // Mark as updated

            std::thread update_arp_n6([this, upf_xdp_program, dn_ip, upf_n6_ip,
                                       pdr_id, seid]() {
              try {
                char buf_dn_ip[INET_ADDRSTRLEN];
                struct in_addr addr_dn_ip = {.s_addr = dn_ip};
                inet_ntop(AF_INET, &addr_dn_ip, buf_dn_ip, INET_ADDRSTRLEN);

                std::string mac =
                    UpdateArpTableForN6(upf_xdp_program, dn_ip, upf_n6_ip);
                Logger::upf_app().debug(
                    "ARP: %s dev %s lladdr %s [SEID=%" PRIu64 "]", buf_dn_ip,
                    upf::GetN6Iface().c_str(), mac.c_str(), seid);
              } catch (const std::exception& ex) {
                Logger::upf_app().error(
                    "N6 ARP update failed for PDR %u: %s", pdr_id, ex.what());
              }
            });
            update_arp_n6.detach();
          }
        } else if (source_interface.interface_value == INTERFACE_VALUE_CORE) {
          // Downlink PDR - update N3 ARP (toward gNodeB)
          if ((gnb_ip > 0) &&
              (n3_ips_updated.find(gnb_ip) == n3_ips_updated.end())) {
            n3_ips_updated.insert(gnb_ip);  // Mark as updated

            std::thread update_arp_n3([this, upf_xdp_program, gnb_ip, upf_n3_ip,
                                       pdr_id, seid]() {
              try {
                char buf_gnb_ip[INET_ADDRSTRLEN];
                struct in_addr addr_gnb_ip = {.s_addr = gnb_ip};
                inet_ntop(AF_INET, &addr_gnb_ip, buf_gnb_ip, INET_ADDRSTRLEN);

                std::string mac = UpdateArpTableForN3(
                    upf_xdp_program, gnb_ip, upf_n3_ip, seid);
                Logger::upf_app().debug(
                    "ARP: %s dev %s lladdr %s [SEID=%" PRIu64 "]", buf_gnb_ip,
                    upf::GetN3Iface().c_str(), mac.c_str(), seid);
              } catch (const std::exception& ex) {
                Logger::upf_app().error(
                    "N3 ARP update failed for PDR %u: %s", pdr_id, ex.what());
              }
            });
            update_arp_n3.detach();
          }
        }
      }

      // Parse SDF Filter for traffic classification (if QER present)
      if (pdr->qer_id.first) {
        pfcp::sdf_filter_t sdf;
        struct sdf_filtr sdf_filter;
        std::string flow_description;

        if (pdr->get(pdi) && pdi.get(sdf)) {
          if (sdf.fd && sdf.length_of_flow_description > 0)
            flow_description = sdf.flow_description;

          // Get QFI from QER
          uint32_t qfi = 0;
          if (qer && qer->qos_flow_id.first) {
            qfi = qer->qos_flow_id.second.qfi;
          }

          // Inject QFI into PDI if available
          if (qfi != 0) {
            pdi.qfi.first      = true;
            pdi.qfi.second.qfi = qfi;
            pdr->set(pdi);
          }

          // Parse and store SDF filter
          auto filter_info = SdfFilterParser::ParseSdfFilter(flow_description);
          if (filter_info) {
            sdf_filter              = *filter_info;
            sdf_filter.session.seid = seid;
            sdf_filter.session.qfi  = qfi;

            struct session_qfi sdf_key = {0};
            sdf_key.qfi                = qfi;
            sdf_key.seid               = seid;

            auto sdf_map = upf_xdp_program->GetSdfFilterMap();
            if (sdf_map) {
              sdf_map->Update(sdf_key, sdf_filter, BPF_ANY);
            }
          } else {
            logger.warn(
                "Failed to parse SDF filter for PDR %u: '%s'", pdr_id,
                flow_description.c_str());
          }
        }
      }

      // Store PDR in array for batch update
      pdrs[pdr_index] = bpf_pdr;
      pdr_index++;
    }

    // Store all PDRs in session map (batch update)
    // Store all PDRs in correct session PDR map
    const char* pdrs_map_name =
        is_eth_pdu ? "eth_session_pdrs_map" : "pdrs_per_session_map";
    auto session_pdrs_map = upf_xdp_program->GetMapByName(pdrs_map_name);
    if (session_pdrs_map) {
      session_pdrs_map->Update(seid, pdrs, BPF_ANY);
    }

    logger.info(
        "[eBPF] Modify Pipeline - Pipeline modified for session " SEID_FMT
        " with %d PDRs (%zu uplink TEIDs, %zu downlink TEIDs)",
        seid, pdr_index, uplink_teids.size(), downlink_teids.size());

  } catch (const std::exception& e) {
    logger.error(
        "[eBPF] Modify Pipeline - Failed for session " SEID_FMT ": %s", seid,
        e.what());
    throw;  // Re-throw to caller
  }
}

//------------------------------------------------------------------------------
/**
 * @brief Remove BPF pipeline for a session
 *
 * Tears down BPF maps and programs for the specified session.
 * Delegates to RemoveSession() for actual cleanup.
 *
 * @param seid Session Endpoint Identifier
 *
 * @see 3GPP TS 29.244 Section 7.5.6 - PFCP Session Deletion
 */
void SessionProgramManager::RemovePipeline(uint64_t seid) {
  Logger::upf_app().info("Removing pipeline for session " SEID_FMT, seid);

  try {
    RemoveSession(seid);
    Logger::upf_app().info("Pipeline removed for session " SEID_FMT, seid);

  } catch (const std::exception& e) {
    Logger::upf_app().error(
        "RemovePipeline failed for session " SEID_FMT ": %s", seid, e.what());
  }
}

//------------------------------------------------------------------------------
// PFCP IE to BPF Conversion - 3GPP TS 29.244 Section 8.2
//------------------------------------------------------------------------------

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
struct pfcp_far SessionProgramManager::ConvertFar(
    std::shared_ptr<pfcp::pfcp_far> far) const {
  struct pfcp_far bpf_far = {};

  if (!far) return bpf_far;

  // FAR ID (3GPP TS 29.244 Section 8.2.74)
  bpf_far.far_id.far_id = far->far_id.far_id;

  // Apply Action (3GPP TS 29.244 Section 8.2.26)
  // memcpy(
  //     &bpf_far.apply_action, &far->apply_action, sizeof(struct
  //     apply_action));
  bpf_far.apply_action.drop  = far->apply_action.drop ? 1 : 0;
  bpf_far.apply_action.forw  = far->apply_action.forw ? 1 : 0;
  bpf_far.apply_action.buff  = far->apply_action.buff ? 1 : 0;
  bpf_far.apply_action.nocp  = far->apply_action.nocp ? 1 : 0;
  bpf_far.apply_action.dupl  = far->apply_action.dupl ? 1 : 0;
  bpf_far.apply_action.spare = 0;

  // Forwarding Parameters (3GPP TS 29.244 Section 8.2.74)
  if (far->forwarding_parameters.first) {
    bpf_far.forwarding_parameters.destination_interface.interface_value =
        far->forwarding_parameters.second.destination_interface.second
            .interface_value;

    // Outer Header Creation (3GPP TS 29.244 Section 8.2.74)
    if (far->forwarding_parameters.second.outer_header_creation.first) {
      bpf_far.forwarding_parameters.outer_header_creation.teid =
          far->forwarding_parameters.second.outer_header_creation.second.teid;

      bpf_far.forwarding_parameters.outer_header_creation.port_number =
          far->forwarding_parameters.second.outer_header_creation.second
              .port_number;

      bpf_far.forwarding_parameters.outer_header_creation.description =
          far->forwarding_parameters.second.outer_header_creation.second
              .outer_header_creation_description;

      bpf_far.forwarding_parameters.outer_header_creation.ipv4_address.s_addr =
          far->forwarding_parameters.second.outer_header_creation.second
              .ipv4_address.s_addr;
    }
  }

  return bpf_far;
}

//------------------------------------------------------------------------------
/**
 * @brief Convert PFCP PDR to BPF PDR structure
 *
 * Translates Packet Detection Rule IE (3GPP TS 29.244 Section 8.2.2)
 * into BPF-compatible structure for packet classification.
 *
 * Key fields converted:
 * - PDI (Packet Detection Information)
 * - Precedence (3GPP TS 29.244 Section 8.2.29)
 * - FAR ID, QER ID, URR ID references
 * - SDF Filter (3GPP TS 29.244 Section 8.2.32)
 *
 * @param pdr PFCP PDR object (nullptr returns zeroed struct)
 * @return BPF PDR structure
 *
 * @see 3GPP TS 29.244 Section 8.2.2 - Create PDR IE
 */
struct pfcp_pdr SessionProgramManager::ConvertPdr(
    std::shared_ptr<pfcp::pfcp_pdr> pdr) const {
  struct pfcp_pdr bpf_pdr = {};

  if (!pdr) return bpf_pdr;

  // PDR ID and Precedence (3GPP TS 29.244 Section 8.2.29)
  bpf_pdr.pdr_id.rule_id        = pdr->pdr_id.rule_id;
  bpf_pdr.precedence.precedence = pdr->precedence.second.precedence;

  // Associated rule IDs
  bpf_pdr.far_id.far_id = pdr->far_id.second.far_id;
  bpf_pdr.qer_id.qer_id = pdr->qer_id.second.qer_id;
  bpf_pdr.urr_id        = pdr->urr_id.second.urr_id;

  // PDI (Packet Detection Information)
  if (pdr->pdi.first) {
    // Source Interface (3GPP TS 29.244 Section 8.2.62)
    bpf_pdr.pdi.source_interface.interface_value =
        pdr->pdi.second.source_interface.second.interface_value;

    // F-TEID (3GPP TS 29.244 Section 8.2.3)
    if (pdr->pdi.second.local_fteid.first) {
      bpf_pdr.pdi.fteid.teid = pdr->pdi.second.local_fteid.second.teid;
    }

    // UE IP Address (3GPP TS 29.244 Section 8.2.62)
    if (pdr->pdi.second.ue_ip_address.first) {
      bpf_pdr.pdi.ue_ip_address.ipv4_address.s_addr =
          pdr->pdi.second.ue_ip_address.second.ipv4_address.s_addr;
    }

    // SDF Filter (3GPP TS 29.244 Section 8.2.5)
    if (pdr->pdi.second.sdf_filter.first) {
      bpf_pdr.pdi.sdf_filter.flow_desc_len =
          pdr->pdi.second.sdf_filter.second.length_of_flow_description;

      try {
        if (bpf_pdr.pdi.sdf_filter.flow_desc_len >=
            sizeof(bpf_pdr.pdi.sdf_filter.flow_description)) {
          Logger::upf_app().debug(
              "SDF Filter Lengh (%d) exceeds buffer size (%d), Truncating "
              "data.",
              bpf_pdr.pdi.sdf_filter.flow_desc_len,
              sizeof(pdr->pdi.second.sdf_filter.second.flow_description));

          throw std::runtime_error("SDF filter length exceeds buffer size.");
        }

        memcpy(
            bpf_pdr.pdi.sdf_filter.flow_description,
            pdr->pdi.second.sdf_filter.second.flow_description.c_str(),
            bpf_pdr.pdi.sdf_filter.flow_desc_len);

      } catch (const std::bad_alloc& e) {
        // Handle memory allocation failure
        Logger::upf_app().error(
            "Memory allocation failed while copying SDF filter: {}", e.what());

        throw;  // Rethrow the exception
      } catch (const std::exception& e) {
        // Catch any other exception
        Logger::upf_app().error(
            "An error occurred while processing the SDF filter: {}", e.what());

        throw;  // Rethrow the exception
      } catch (...) {
        // Catch all other unspecified errors
        Logger::upf_app().error(
            "An unexpected error occurred while copying the SDF filter.");

        throw std::runtime_error(
            "Unexpected error occurred while copying SDF filter.");
      }
    }

    // QFI (3GPP TS 29.244 Section 8.2.89)
    if (pdr->pdi.second.qfi.first) {
      bpf_pdr.pdi.qfi.qfi = pdr->pdi.second.qfi.second.qfi;
    }
  }

  // if (pdr->activate_predefined_rules.first) {
  //   memcpy(
  //       &bpf_pdr.activate_predefined_rules, &pdr->activate_predefined_rules,
  //       sizeof(struct activate_predefined_rules));
  // }

  if (pdr->outer_header_removal.first) {
    memcpy(
        &bpf_pdr.outer_header_removal, &pdr->outer_header_removal,
        sizeof(struct outer_header_removal));
  }

  return bpf_pdr;
}

//------------------------------------------------------------------------------
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
struct pfcp_qer SessionProgramManager::ConvertQer(
    std::shared_ptr<pfcp::pfcp_qer> qer) const {
  struct pfcp_qer bpf_qer = {};

  if (!qer) return bpf_qer;

  // QER ID (3GPP TS 29.244 Section 8.2.11)
  bpf_qer.qer_id.qer_id = qer->qer_id.second.qer_id;

  // Gate Status (3GPP TS 29.244 Section 8.2.25)
  if (qer->gate_status.first) {
    bpf_qer.gate_status.ul_gate = qer->gate_status.second.ul_gate;
    bpf_qer.gate_status.dl_gate = qer->gate_status.second.dl_gate;
  }

  // MBR - Maximum Bitrate (3GPP TS 29.244 Section 8.2.40)
  if (qer->maximum_bitrate.first) {
    bpf_qer.maximum_bitrate.ul_mbr = qer->maximum_bitrate.second.ul_mbr;
    bpf_qer.maximum_bitrate.dl_mbr = qer->maximum_bitrate.second.dl_mbr;
  }

  // GBR - Guaranteed Bitrate (3GPP TS 29.244 Section 8.2.41)
  if (qer->guaranteed_bitrate.first) {
    bpf_qer.guaranteed_bitrate.ul_gbr = qer->guaranteed_bitrate.second.ul_gbr;
    bpf_qer.guaranteed_bitrate.dl_gbr = qer->guaranteed_bitrate.second.dl_gbr;
  }

  // QFI (3GPP TS 29.244 Section 8.2.89)
  if (qer->qos_flow_id.first) {
    bpf_qer.qos_flow_identifier.qfi = qer->qos_flow_id.second.qfi;
  }

  // if (qer->qer_correlation_id.first) {
  //   bpf_qer.qer_correlation_id.qer_correlation_id =
  //       qer->qer_correlation_id.second.qer_correlation_id;
  // }

  if (qer->reflective_qos.first) {
    bpf_qer.reflective_qos.rqi = qer->reflective_qos.second.rqi;
  }

  return bpf_qer;
}

//------------------------------------------------------------------------------
/**
 * @brief Convert PFCP URR to BPF URR structure
 *
 * Translates Usage Reporting Rule IE (3GPP TS 29.244 Section 8.2.5)
 * into BPF-compatible structure for usage measurement and reporting.
 *
 * Key fields converted:
 * - URR ID (3GPP TS 29.244 Section 8.2.44)
 * - Reporting Triggers bitmask (3GPP TS 29.244 Section 8.2.53)
 * - Volume Threshold (3GPP TS 29.244 Section 8.2.48)
 * - Volume Quota (3GPP TS 29.244 Section 8.2.46)
 * - Measurement Period (3GPP TS 29.244 Section 8.2.72)
 * - Time Threshold (3GPP TS 29.244 Section 8.2.48)
 * - Monitoring Time (3GPP TS 29.244 Section 8.2.67)
 *
 * @note Time fields are converted from seconds to nanoseconds for
 *       bpf_ktime_get_ns() comparison in the data path.
 *
 * @param urr PFCP URR object (nullptr returns zeroed struct)
 * @return BPF URR structure
 *
 * @see 3GPP TS 29.244 Section 8.2.5 - Create URR IE
 */
struct pfcp_urr SessionProgramManager::ConvertUrr(
    std::shared_ptr<pfcp::pfcp_urr> urr) const {
  struct pfcp_urr bpf_urr = {};

  if (!urr) return bpf_urr;

  bpf_urr.urr_id = urr->urr_id.second.urr_id;

  // Reporting Triggers (Section 8.2.53)
  if (urr->reporting_triggers.first) {
    bpf_urr.reporting_triggers.volth =
        urr->reporting_triggers.second.volth ? 1 : 0;
    bpf_urr.reporting_triggers.volqu =
        urr->reporting_triggers.second.volqu ? 1 : 0;
    bpf_urr.reporting_triggers.timth =
        urr->reporting_triggers.second.timth ? 1 : 0;
    bpf_urr.reporting_triggers.timqu =
        urr->reporting_triggers.second.timqu ? 1 : 0;
    bpf_urr.reporting_triggers.perio =
        urr->reporting_triggers.second.perio ? 1 : 0;
    bpf_urr.reporting_triggers.start =
        urr->reporting_triggers.second.start ? 1 : 0;
    bpf_urr.reporting_triggers.stop =
        urr->reporting_triggers.second.stop ? 1 : 0;
    bpf_urr.reporting_triggers.droth =
        urr->reporting_triggers.second.droth ? 1 : 0;
  }

  // Volume Threshold (Section 8.2.48)
  if (urr->volume_threshold.first) {
    bpf_urr.volume_threshold.total_volume =
        urr->volume_threshold.second.total_volume;
    bpf_urr.volume_threshold.uplink_volume =
        urr->volume_threshold.second.uplink_volume;
    bpf_urr.volume_threshold.downlink_volume =
        urr->volume_threshold.second.downlink_volume;
  }

  // Volume Quota (Section 8.2.46)
  if (urr->volume_quota.first) {
    bpf_urr.volume_quota.total_volume  = urr->volume_quota.second.total_volume;
    bpf_urr.volume_quota.uplink_volume = urr->volume_quota.second.uplink_volume;
    bpf_urr.volume_quota.downlink_volume =
        urr->volume_quota.second.downlink_volume;
  }

  // Measurement Period (Section 8.2.72) — convert seconds to nanoseconds
  if (urr->measurement_period.first) {
    bpf_urr.measurement_period.measurement_period =
        static_cast<uint64_t>(
            urr->measurement_period.second.measurement_period) *
        1000000000ULL;
  }

  // Time Threshold (Section 8.2.48) — convert seconds to nanoseconds
  if (urr->time_threshold.first) {
    bpf_urr.time_threshold.time_threshold =
        static_cast<uint64_t>(urr->time_threshold.second.time_threshold) *
        1000000000ULL;
  }

  // Monitoring Time (Section 8.2.67) — convert NTP epoch to nanoseconds
  if (urr->monitoring_time.first) {
    bpf_urr.monitoring_time.monitoring_time =
        static_cast<uint64_t>(urr->monitoring_time.second.monitoring_time) *
        1000000000ULL;
  }

  // Dropped DL Traffic Threshold (Section 8.2.49)
  if (urr->dropped_dl_traffic_threshold.first) {
    const auto& ddth = urr->dropped_dl_traffic_threshold.second;
    bpf_urr.dropped_dl_traffic_threshold.flags = 0;

    if (ddth.dlpa) {
      bpf_urr.dropped_dl_traffic_threshold.flags |= DDTH_FLAG_DLPA;
      bpf_urr.dropped_dl_traffic_threshold.downlink_packets =
          ddth.downlink_packets;
    }
    if (ddth.dlby) {
      bpf_urr.dropped_dl_traffic_threshold.flags |= DDTH_FLAG_DLBY;
      bpf_urr.dropped_dl_traffic_threshold.number_of_bytes_of_downlink_data =
          ddth.number_of_bytes_of_downlink_data;
    }
  }

  return bpf_urr;
}

//------------------------------------------------------------------------------
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
 */
struct pfcp_bar SessionProgramManager::ConvertBar(
    std::shared_ptr<pfcp::pfcp_bar> bar) const {
  struct pfcp_bar bpf_bar = {};

  if (!bar) return bpf_bar;

  bpf_bar.bar_id = bar->bar_id.second.bar_id;

  // Suggested Buffering Packets Count (Section 8.2.50)
  if (bar->suggested_buffering_packets_count.first) {
    bpf_bar.suggested_buffering_packets_count.packet_count =
        bar->suggested_buffering_packets_count.second.packet_count;
  }

  // DL Data Notification Delay (Section 8.2.28) — in seconds
  if (bar->downlink_data_notification_delay.first) {
    bpf_bar.dl_data_notification_delay.delay_value =
        bar->downlink_data_notification_delay.second.delay_value;
  }

  return bpf_bar;
}

//------------------------------------------------------------------------------
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
struct pfcp_mar SessionProgramManager::ConvertMar(
    std::shared_ptr<pfcp::pfcp_mar> mar) const {
  struct pfcp_mar bpf_mar = {};

  if (!mar) return bpf_mar;

  bpf_mar.mar_id = mar->mar_id.second.mar_id;

  // Steering Mode (Section 8.2.124)
  if (mar->steering_mode.first) {
    bpf_mar.steering_mode.steer_mode_value =
        mar->steering_mode.second.steering_mode_value;
  }

  // Access Forwarding Action Information - 3GPP (Section 8.2.75)
  if (mar->access_forwarding_action_info_1.first) {
    bpf_mar.access_forwarding_action_info_1.far_id.far_id =
        mar->access_forwarding_action_info_1.second.far_id.far_id;
  }

  // Access Forwarding Action Information - Non-3GPP (Section 8.2.76)
  if (mar->access_forwarding_action_info_2.first) {
    bpf_mar.access_forwarding_action_info_2.far_id.far_id =
        mar->access_forwarding_action_info_2.second.far_id.far_id;
  }

  return bpf_mar;
}

// struct pfcp_mar {
//   __u16 mar_id;
//   struct steering_functionality steering_functionality;
//   struct steering_mode steering_mode;
//   struct access_forwarding_action_info access_forwarding_action_info_1;
//   struct access_forwarding_action_info access_forwarding_action_info_2;
// } __attribute__((packed));

//------------------------------------------------------------------------------
// Rule Retrieval Helpers
//------------------------------------------------------------------------------

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
bool SessionProgramManager::GetUrrForPdr(
    std::shared_ptr<pfcp::pfcp_session> session,
    std::shared_ptr<pfcp::pfcp_pdr> pdr,
    std::shared_ptr<pfcp::pfcp_urr>& out_urr) const {
  pfcp::urr_id_t urr_id;
  return (
      pdr->get(urr_id) &&
      session->get(static_cast<uint32_t>(urr_id.urr_id), out_urr));
}

//------------------------------------------------------------------------------
/**
 * @brief Retrieve BAR associated with a FAR
 *
 * Follows the FAR -> BAR ID -> session BAR lookup chain.
 * BAR is referenced from FAR (not PDR) because buffering is a
 * forwarding action property (3GPP TS 29.244 Section 8.2.49).
 * Only applicable when far->apply_action.buff is set.
 *
 * @param session PFCP session containing BAR definitions
 * @param far FAR whose bar_id to follow
 * @param[out] out_bar Populated with matching BAR, or nullptr if not found
 * @return true if BAR found, false otherwise
 *
 * @see 3GPP TS 29.244 Section 8.2.49 - BAR ID
 * @see 3GPP TS 29.244 Section 8.2.26 - Apply Action (buff bit)
 */
bool SessionProgramManager::GetBarForFar(
    std::shared_ptr<pfcp::pfcp_session> session,
    std::shared_ptr<pfcp::pfcp_far> far,
    std::shared_ptr<pfcp::pfcp_bar>& out_bar) const {
  // BAR is referenced from FAR, not PDR (Section 8.2.49)
  if (!far || !far->bar_id.first) return false;
  return session->get(static_cast<uint8_t>(far->bar_id.second.bar_id), out_bar);
}

//------------------------------------------------------------------------------
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
bool SessionProgramManager::GetMarForPdr(
    std::shared_ptr<pfcp::pfcp_session> session,
    std::shared_ptr<pfcp::pfcp_pdr> pdr,
    std::shared_ptr<pfcp::pfcp_mar>& out_mar) const {
  pfcp::mar_id_t mar_id;
  return (
      pdr->get(mar_id) &&
      session->get(static_cast<uint8_t>(mar_id.mar_id), out_mar));
}

//------------------------------------------------------------------------------
// Dedicated BPF Map Population — Runtime State Initialization
//------------------------------------------------------------------------------

/**
 * @brief Populate urr_config_map and initialize urr_volume_counters_map
 *
 * Stores the URR configuration in the BPF urr_config_map (key: SEID)
 * for threshold/quota checking by the data path (urr_apply.c).
 *
 * Also initializes urr_volume_counters_map (volume counters) to zero using
 * BPF_NOEXIST to avoid overwriting counters for active measurements
 * during session modification.
 *
 * @param upf_xdp_program XDP program containing the BPF maps
 * @param seid Session Endpoint Identifier (map key)
 * @param urr_config Converted URR configuration to store
 *
 * @see 3GPP TS 29.244 Section 8.2.44-48 - URR IEs
 */
void SessionProgramManager::PopulateUrrConfigMap(
    std::shared_ptr<UPF_XDPProgram> upf_xdp_program, uint64_t seid,
    const struct pfcp_urr& urr_config) {
  if (!upf_xdp_program) return;

  // Store config in urr_config_map (key: seid)
  auto cfg_map = upf_xdp_program->GetMapByName("urr_config_map");
  if (cfg_map) {
    int ret = cfg_map->Update(seid, urr_config, BPF_ANY);
    if (ret != 0) {
      Logger::upf_app().error(
          "Failed to update urr_config_map for SEID=" SEID_FMT, seid);
    }
  }

  // Initialize volume counters to zero (key: seid)
  auto vol_map = upf_xdp_program->GetMapByName("urr_volume_counters_map");
  if (vol_map) {
    // urr_volume is {ul_bytes, dl_bytes, ul_packets, dl_packets,
    //                total_bytes, total_packets} — all zero
    uint8_t zeros[48] = {0};                    // sizeof(urr_volume) = 48
    vol_map->Update(seid, zeros, BPF_NOEXIST);  // Don't overwrite existing
  }

  Logger::upf_app().debug(
      "URR config populated for SEID=" SEID_FMT
      " URR_ID=%u "
      "[volth=%u timth=%u perio=%u]",
      seid, urr_config.urr_id, (unsigned) urr_config.reporting_triggers.volth,
      (unsigned) urr_config.reporting_triggers.timth,
      (unsigned) urr_config.reporting_triggers.perio);
}

//------------------------------------------------------------------------------
/**
 * @brief Populate bar_config_map and initialize bar_state_map
 *
 * Stores the BAR configuration in the BPF bar_config_map (key: SEID)
 * for DDN suppression and buffer overflow control by bar_apply.c.
 *
 * Also initializes bar_state_map (DDN tracking, pkt count) to zero
 * using BPF_NOEXIST to avoid overwriting active buffering state.
 *
 * @param upf_xdp_program XDP program containing the BPF maps
 * @param seid Session Endpoint Identifier (map key)
 * @param bar_config Converted BAR configuration to store
 *
 * @see 3GPP TS 29.244 Section 8.2.49-50 - BAR IEs
 * @see 3GPP TS 29.244 Section 8.2.28 - DL Data Notification Delay
 */
void SessionProgramManager::PopulateBarConfigMap(
    std::shared_ptr<UPF_XDPProgram> upf_xdp_program, uint64_t seid,
    const struct pfcp_bar& bar_config) {
  if (!upf_xdp_program) return;

  // Store config in bar_config_map (key: seid)
  auto cfg_map = upf_xdp_program->GetMapByName("bar_config_map");
  if (cfg_map) {
    int ret = cfg_map->Update(seid, bar_config, BPF_ANY);
    if (ret != 0) {
      Logger::upf_app().error(
          "Failed to update bar_config_map for SEID=" SEID_FMT, seid);
    }
  }

  // Initialize buffering state to zero (key: seid)
  auto st_map = upf_xdp_program->GetMapByName("bar_state_map");
  if (st_map) {
    // bar_state is {last_ddn_ns, buffered_pkt_count,
    //               notification_sent, pad[3]} — all zero
    uint8_t zeros[16] = {0};                   // sizeof(bar_state) = 16
    st_map->Update(seid, zeros, BPF_NOEXIST);  // Don't overwrite existing
  }

  Logger::upf_app().debug(
      "BAR config populated for SEID=" SEID_FMT
      " BAR_ID=%u "
      "[buf_pkt_cnt=%u, notify_delay=%us]",
      seid, bar_config.bar_id,
      (unsigned) bar_config.suggested_buffering_packets_count.packet_count,
      (unsigned) bar_config.dl_data_notification_delay.delay_value);
}

//------------------------------------------------------------------------------
/**
 * @brief Populate mar_rules_map for a session
 *
 * Stores the MAR configuration in the BPF mar_rules_map (key: SEID).
 * The data path (mar_apply.c) reads this map to determine the ATSSS
 * steering mode and access forwarding FAR IDs.
 *
 * @param upf_xdp_program XDP program containing the BPF maps
 * @param seid Session Endpoint Identifier (map key)
 * @param mar_rule Converted MAR configuration to store
 *
 * @see 3GPP TS 29.244 Section 8.2.74-76 - MAR IEs
 * @see 3GPP TS 23.501 Section 5.32 - ATSSS
 */
void SessionProgramManager::PopulateMarRulesMap(
    std::shared_ptr<UPF_XDPProgram> upf_xdp_program, uint64_t seid,
    const struct pfcp_mar& mar_rule) {
  if (!upf_xdp_program) return;

  auto mar_map = upf_xdp_program->GetMapByName("mar_rules_map");
  if (mar_map) {
    int ret = mar_map->Update(seid, mar_rule, BPF_ANY);
    if (ret != 0) {
      Logger::upf_app().error(
          "Failed to update mar_rules_map for SEID=" SEID_FMT, seid);
    }
  }

  Logger::upf_app().debug(
      "MAR config populated for SEID=" SEID_FMT
      " MAR_ID=%u "
      "[steer_mode=%u, afai1_far=%u, afai2_far=%u]",
      seid, mar_rule.mar_id, (unsigned) mar_rule.steering_mode.steer_mode_value,
      (unsigned) mar_rule.access_forwarding_action_info_1.far_id.far_id,
      (unsigned) mar_rule.access_forwarding_action_info_2.far_id.far_id);
}

//------------------------------------------------------------------------------
// ARP Table Management - RFC 826
//------------------------------------------------------------------------------

// // 3GPP TS 23.501 Section 5.8.2.3 - N6 Interface
// void SessionProgramManager::UpdateArpTableForN6(
//     std::shared_ptr<UPF_XDPProgram> upf_xdp_program, uint32_t dn_ip,
//     uint32_t upf_n6_ip) {
//   if (!upf_xdp_program) {
//     Logger::upf_app().error("UpdateArpTable: no XDP program available");
//     return;
//   }

//   try {
//     // Get next hop IP (remote endpoint or gateway)
//     uint32_t remote_ip = GetNextHopIp(upf_n6_ip, dn_ip);

//     // Convert to proper endianness for MAC lookup
//     uint32_t ip_for_mac_lookup =
//         (likely(IsLittleEndian())) ? htole32(remote_ip) : remote_ip;

//     // Retrieve MAC address from ARP cache/routing table
//     auto remote_mac = NextHopFinder::retrieveNextHopMAC(ip_for_mac_lookup);

//     // Populate ARP entry structure
//     struct arp_entry entry;
//     memset(&entry, 0, sizeof(struct arp_entry));
//     memcpy(entry.mac_address, remote_mac,
//            ETH_ALEN);  // Copy 6-byte MAC address
//     entry.ipv4_address = ip_for_mac_lookup;

//     // Update ARP table in BPF map
//     // upf_xdp_program->GetArpTableMap()->Update(upf_n6_ip, entry,
//     BPF_ANY); auto arp_table_map =
//     upf_xdp_program->GetMapByName("arp_table_map"); if (arp_table_map) {
//       arp_table_map->Update(upf_n6_ip, entry, BPF_ANY);
//     } else {
//       Logger::upf_app().error("UpdateArpTable: arp_table map not found");
//     }

//   } catch (const std::exception& ex) {
//     Logger::upf_app().error(
//         "Error: The ARP table was not updated for N6 Next HOP: %s",
//         ex.what());
//   }
// }

/**
 * @brief Update ARP table for N6 interface (toward Data Network)
 *
 * Resolves the MAC address of the next hop toward the DN and stores
 * it in the BPF arp_table_map for L2 header rewriting.
 *
 * @param upf_xdp_program XDP program containing arp_table_map
 * @param dn_ip Data Network IP address (destination)
 * @param upf_n6_ip UPF N6 interface IP address (source)
 * @return MAC address string of resolved next hop
 *
 * @see RFC 826 - Address Resolution Protocol
 * @see 3GPP TS 23.501 Section 5.8.2.3 - N6 Interface
 */
std::string SessionProgramManager::UpdateArpTableForN6(
    std::shared_ptr<UPF_XDPProgram> upf_xdp_program, uint32_t dn_ip,
    uint32_t upf_n6_ip) {
  if (!upf_xdp_program) {
    Logger::upf_app().error("UpdateArpTable: no XDP program available");
    return "00:00:00:00:00:00";
  }

  try {
    // Get next hop IP (remote endpoint or gateway)
    uint32_t remote_ip = GetNextHopIp(upf_n6_ip, dn_ip);

    // Convert to proper endianness for MAC lookup
    uint32_t ip_for_mac_lookup =
        (likely(IsLittleEndian())) ? htole32(remote_ip) : remote_ip;

    // Retrieve MAC address from ARP cache/routing table
    auto remote_mac = NextHopFinder::retrieveNextHopMAC(ip_for_mac_lookup);

    // Format MAC as string
    char mac_str[18];
    snprintf(
        mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
        remote_mac->ether_addr_octet[0], remote_mac->ether_addr_octet[1],
        remote_mac->ether_addr_octet[2], remote_mac->ether_addr_octet[3],
        remote_mac->ether_addr_octet[4], remote_mac->ether_addr_octet[5]);

    // Populate ARP entry structure
    struct arp_entry entry;
    memset(&entry, 0, sizeof(struct arp_entry));
    memcpy(entry.mac_address, remote_mac, ETH_ALEN);
    entry.ipv4_address = ip_for_mac_lookup;

    // Update ARP table in BPF map
    auto arp_table_map = upf_xdp_program->GetMapByName("arp_table_map");
    if (arp_table_map) {
      arp_table_map->Update(upf_n6_ip, entry, BPF_ANY);
    } else {
      Logger::upf_app().error("UpdateArpTable: arp_table map not found");
    }

    return std::string(mac_str);

  } catch (const std::exception& ex) {
    Logger::upf_app().error(
        "Error: The ARP table was not updated for N6 Next HOP: %s", ex.what());
    return "00:00:00:00:00:00";
  }
}

//------------------------------------------------------------------------------
/**
 * @brief Update ARP table for N3 interface (toward gNodeB)
 *
 * Resolves the MAC address of the next hop toward the gNB and stores
 * it in the BPF arp_table_map for L2 header rewriting.
 *
 * @param upf_xdp_program XDP program containing arp_table_map
 * @param gnb_ip gNodeB IP address (destination)
 * @param upf_n3_ip UPF N3 interface IP address (source)
 * @param seid Session Endpoint Identifier
 * @return MAC address string of resolved next hop
 *
 * @see RFC 826 - Address Resolution Protocol
 * @see 3GPP TS 23.501 Section 5.8.2.2 - N3 Interface
 */
std::string SessionProgramManager::UpdateArpTableForN3(
    std::shared_ptr<UPF_XDPProgram> upf_xdp_program, uint32_t gnb_ip,
    uint32_t upf_n3_ip, uint64_t seid) {
  if (!upf_xdp_program) {
    Logger::upf_app().error("UpdateArpTable: no XDP program available");
    return "00:00:00:00:00:00";
  }

  try {
    // Get next hop IP (gNB or gateway)
    uint32_t remote_ip = GetNextHopIp(upf_n3_ip, gnb_ip);

    // Convert to proper endianness for MAC lookup
    uint32_t ip_for_mac_lookup =
        (likely(IsLittleEndian())) ? htole32(remote_ip) : remote_ip;

    // Retrieve MAC address from ARP cache/routing table
    auto remote_mac = NextHopFinder::retrieveNextHopMAC(ip_for_mac_lookup);

    // Format MAC as string
    char mac_str[18];
    snprintf(
        mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
        remote_mac->ether_addr_octet[0], remote_mac->ether_addr_octet[1],
        remote_mac->ether_addr_octet[2], remote_mac->ether_addr_octet[3],
        remote_mac->ether_addr_octet[4], remote_mac->ether_addr_octet[5]);

    // Populate ARP entry structure
    struct arp_entry entry;
    memset(&entry, 0, sizeof(struct arp_entry));
    memcpy(entry.mac_address, remote_mac, ETH_ALEN);
    entry.ipv4_address = ip_for_mac_lookup;

    // Update ARP table in BPF map
    auto arp_table_map = upf_xdp_program->GetMapByName("arp_table_map");
    if (arp_table_map) {
      arp_table_map->Update(upf_n3_ip, entry, BPF_ANY);
    }

    for (auto it = pfcp_programs->begin(); it != pfcp_programs->end(); ++it) {
      uint64_t savedSeid                              = it->seid;
      std::shared_ptr<UPF_XDPProgram> upf_xdp_program = it->upf_xdp_program;

      if (savedSeid == seid) {
        auto arp_table_map = upf_xdp_program->GetMapByName("arp_table_map");
        if (arp_table_map) {
          arp_table_map->Update(upf_n3_ip, entry, BPF_ANY);
        } else {
          Logger::upf_app().error("UpdateArpTable: arp_table map not found");
        }
      }
    }

    return std::string(mac_str);

  } catch (const std::exception& ex) {
    Logger::upf_app().error(
        "Error: The ARP table was not updated for N3 Next HOP: %s", ex.what());
    return "00:00:00:00:00:00";
  }
}

//------------------------------------------------------------------------------
/**
 * @brief Determine next hop IP for routing
 *
 * If local and remote IPs are on the same subnet, returns remote_ip
 * directly. Otherwise, queries the routing table for the gateway IP.
 *
 * @param local_ip Local interface IP
 * @param remote_ip Remote destination IP
 * @return Next hop IP address (gateway or direct)
 */
uint32_t SessionProgramManager::GetNextHopIp(
    uint32_t local_ip, uint32_t remote_ip) const {
  if (NextHopFinder::sameSubnet(local_ip, remote_ip)) {
    return remote_ip;  // Direct connection
  } else {
    return NextHopFinder::retrieveNextHopIP(remote_ip);  // Via gateway
  }
}

//------------------------------------------------------------------------------
// Session Query Methods
//------------------------------------------------------------------------------

/**
 * @brief Register a PFCP program for a session
 *
 * @param seid Session Endpoint Identifier
 * @param upf_xdp_program XDP program to associate with this session
 */
void SessionProgramManager::AddPfcpProgram(
    uint64_t seid, std::shared_ptr<UPF_XDPProgram> upf_xdp_program) {
  // TODO: re-enable mutex when deadlock risk from callers has been assessed
  // std::lock_guard<std::mutex> lock(mutex_);

  PfcpProgramInfo pfcp_prgm;
  pfcp_prgm.seid            = seid;
  pfcp_prgm.upf_xdp_program = upf_xdp_program;

  pfcp_programs->push_back(pfcp_prgm);
}

//------------------------------------------------------------------------------
/**
 * @brief Find session programs by SEID
 *
 * @param seid Session Endpoint Identifier
 * @return Session programs or nullptr if not found
 */
std::shared_ptr<SessionPrograms> SessionProgramManager::FindSessionPrograms(
    uint64_t seid) const {
  // TODO: re-enable mutex when deadlock risk from callers has been assessed
  // std::lock_guard<std::mutex> lock(mutex_);

  auto it = session_programs_map_.find(seid);
  return (it != session_programs_map_.end()) ? it->second : nullptr;
}

//------------------------------------------------------------------------------
/**
 * @brief Extract gNodeB IP from FAR's Outer Header Creation
 *
 * Reads the outer_header_creation.ipv4_address from the FAR's
 * forwarding parameters. This is the gNB destination IP for
 * GTP-U encapsulation on the N3 interface.
 *
 * @param far FAR containing forwarding parameters
 * @return gNodeB IPv4 address (network byte order), or 0 if not found
 *
 * @see 3GPP TS 29.244 Section 8.2.74 - Outer Header Creation
 * @throws std::runtime_error if forwarding parameters are absent.
 */
uint32_t SessionProgramManager::GetGnodebIp(
    std::shared_ptr<pfcp::pfcp_far> far) const {
  if (!far) return 0;

  pfcp::forwarding_parameters forward_param;

  if (!far->get(forward_param)) {
    Logger::upf_app().error(
        "Could not retrieve the forwarding parameters from FAR");
    throw std::runtime_error("gNodeB IP cannot be retrieved");
  }

  if (forward_param.outer_header_creation.first) {
    return far->forwarding_parameters.second.outer_header_creation.second
        .ipv4_address.s_addr;
  }

  return 0;
}

//------------------------------------------------------------------------------
/**
 * @brief Retrieve gNodeB IP from session's FARs
 *
 * Scans all FARs for one with destination_interface=ACCESS and
 * Outer Header Creation, extracting the gNodeB IP address.
 *
 * @param session PFCP session to scan
 * @return gNodeB IPv4 address (network byte order), or 0 if not found
 */
uint32_t SessionProgramManager::RetrieveGnbIp(
    std::shared_ptr<pfcp::pfcp_session> session) const {
  if (!session) return 0;

  pfcp::forwarding_parameters forward_param;
  for (const auto& far : session->fars) {
    if (!far->get(forward_param)) continue;

    const auto& dest_iface = forward_param.destination_interface;
    const auto& ohc        = forward_param.outer_header_creation;

    if (dest_iface.first &&
        dest_iface.second.interface_value == INTERFACE_VALUE_ACCESS &&
        ohc.first) {
      return ohc.second.ipv4_address.s_addr;
    }
  }

  // Return 0 if no matching FAR was found
  return 0;
}

//------------------------------------------------------------------------------
/**
 * @brief Retrieve UE IP address from session's PDRs
 *
 * Scans all PDRs for one with a UE IP Address IE in its PDI.
 * Returns 0 for ETH PDU sessions (no UE IP applicable).
 *
 * @param session PFCP session to scan
 * @return UE IPv4 address (network byte order), or 0 if not found
 */
uint32_t SessionProgramManager::RetrieveUeIp(
    std::shared_ptr<pfcp::pfcp_session> session) const {
  if (!session) return 0;

  pfcp::pdi pdi;
  pfcp::ue_ip_address_t ue_ip_address;

  for (const auto& pdr : session->pdrs) {
    if (pdr->get(pdi) && pdi.get(ue_ip_address)) {
      return ue_ip_address.ipv4_address.s_addr;
    }
  }

  return 0;
}

//------------------------------------------------------------------------------
/**
 * @brief Retrieve FAR associated with a PDR
 *
 * Follows the PDR -> FAR ID -> session FAR lookup chain.
 *
 * @param session PFCP session containing FAR definitions
 * @param pdr PDR whose FAR ID to follow
 * @param[out] out_far Populated with matching FAR
 * @return true if FAR found, false otherwise
 *
 * @see 3GPP TS 29.244 Section 8.2.74 - FAR ID
 */
bool SessionProgramManager::GetFarForPdr(
    std::shared_ptr<pfcp::pfcp_session> session,
    std::shared_ptr<pfcp::pfcp_pdr> pdr,
    std::shared_ptr<pfcp::pfcp_far>& out_far) const {
  pfcp::far_id_t far_id;
  return (pdr->get(far_id) && session->get(far_id.far_id, out_far));
}

//------------------------------------------------------------------------------
/**
 * @brief Retrieve QER associated with a PDR
 *
 * Follows the PDR -> QER ID -> session QER lookup chain.
 *
 * @param session PFCP session containing QER definitions
 * @param pdr PDR whose QER ID to follow
 * @param[out] out_qer Populated with matching QER
 * @return true if QER found, false otherwise
 *
 * @see 3GPP TS 29.244 Section §8.2.75 - QER ID
 */
bool SessionProgramManager::GetQerForPdr(
    std::shared_ptr<pfcp::pfcp_session> session,
    std::shared_ptr<pfcp::pfcp_pdr> pdr,
    std::shared_ptr<pfcp::pfcp_qer>& out_qer) const {
  pfcp::qer_id_t qer_id;
  return (pdr->get(qer_id) && session->get(qer_id.qer_id, out_qer));
}

//==============================================================================
// Observer pattern
//==============================================================================

/**
 * @brief Register a session program state observer.
 *
 * TODO: mutex_ is currently not held — see AddPfcpProgram TODO.
 */
void SessionProgramManager::SetSessionObserver(ISessionObserver* observer) {
  // TODO: re-enable mutex when deadlock risk from callers has been assessed
  // std::lock_guard<std::mutex> lock(mutex_);
  session_observer_ = observer;
  Logger::upf_app().debug("Session observer set");
}

//==============================================================================
// Internal helpers
//==============================================================================

int32_t SessionProgramManager::GetEmptySlot() {
  for (size_t i = 0; i < program_array_.size(); ++i) {
    if (program_array_[i] == kEmptySlot) {
      return static_cast<int32_t>(i);
    }
  }
  return -1;
}
