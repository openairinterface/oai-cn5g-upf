/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/**
 * @file SessionProgramManager.cpp
 * @brief BPF Program Manager Implementation
 *
 * Implements BPF/eBPF program management and PFCP IE to BPF structure
 * conversion according to 3GPP TS 29.244 specifications.
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
#include <arp_table.h>
#include <session_id.h>
#include <rules_matching_pdr.h>
#include "logger.hpp"
#include "upf_config.hpp"
#include "pfcp_session.hpp"
#include "pfcp_pdr.hpp"
#include "pfcp_far.hpp"
#include "pfcp_qer.hpp"
#include <pfcp_pdr.h>  // BPF PDR structure
#include <pfcp_far.h>  // BPF FAR structure
#include <pfcp_qer.h>  // BPF QER structure
#include <sdf_filter.h>
#include <mac_pdu_session_key.h>

using namespace oai::config;
using namespace upf::utils;
extern upf_config upf_cfg;

static constexpr int64_t kEmptySlot = -1;

//------------------------------------------------------------------------------
// Constructor & Destructor
//------------------------------------------------------------------------------

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

//------------------------------------------------------------------------------
// Singleton Access
//------------------------------------------------------------------------------

SessionProgramManager& SessionProgramManager::GetInstance() {
  static SessionProgramManager instance;
  return instance;
}

//------------------------------------------------------------------------------
// Session Lifecycle Management
//------------------------------------------------------------------------------

void SessionProgramManager::CreateSession(uint64_t seid) {
  std::lock_guard<std::mutex> lock(mutex_);

  Logger::upf_app().info("Creating session " SEID_FMT, seid);

  // Session-specific initialization if needed
  // The actual BPF maps will be updated in CreatePipeline()
}

//------------------------------------------------------------------------------
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

  // Clean BPF maps so stale entries don't survive across restarts:
  //  - IPv4 per-rule maps (rules_match_pdr_map / sdf_filters_map)
  //  - ETH PDU maps
  try {
    auto xdp = UserPlaneComponent::GetInstance().GetUPF_XDPProgram();
    ClearSessionRuleEntries(xdp, seid);
    if (xdp) {
      auto pdrs_map = xdp->GetSessionPdrsMap();
      if (pdrs_map) {
        try {
          pdrs_map->Remove(seid);
        } catch (...) {
        }
      }
      auto qos_map = xdp->GetQosEnablingMap();
      if (qos_map) {
        try {
          qos_map->Remove(seid);
        } catch (...) {
        }
      }
    }
    RemoveETHPduSessionFromMaps(xdp, seid);
  } catch (const std::exception& e) {
    Logger::upf_app().warn(
        "map cleanup failed for seid %" PRIu64 ": %s", seid, e.what());
  }
}

//------------------------------------------------------------------------------
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

  // Remove session programs
  session_programs_map_.clear();
  pfcp_programs->clear();
  program_array_.fill(kEmptySlot);

  // Clear all ETH PDU BPF maps so pinned maps start clean on next startup
  try {
    auto xdp = UserPlaneComponent::GetInstance().GetUPF_XDPProgram();
    ClearAllETHPduMaps(xdp);
  } catch (const std::exception& e) {
    Logger::upf_app().warn(
        "ETH-PDU: map teardown cleanup failed: %s", e.what());
  }
}

//------------------------------------------------------------------------------
// BPF Map Management
//------------------------------------------------------------------------------

void SessionProgramManager::SetTeidSessionMap(std::shared_ptr<BpfMap> map) {
  std::lock_guard<std::mutex> lock(mutex_);
  teid_session_map_ = map;
}

//------------------------------------------------------------------------------
void SessionProgramManager::SetArpTableMap(std::shared_ptr<BpfMap> map) {
  std::lock_guard<std::mutex> lock(mutex_);
  arp_table_map_ = map;
}

//------------------------------------------------------------------------------
// 3GPP TS 29.281 - Store PDU Session in BPF Map
void SessionProgramManager::StorePduSessionInMap(
    std::shared_ptr<UPF_XDPProgram> xdp_program, uint32_t ue_ip,
    uint32_t teid_ul, uint32_t teid_dl, uint64_t seid) {
  if (!xdp_program) {
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
    // auto session_map = xdp_program->GetMapByName("session_map");
    // if (session_map) {

    auto session_map = xdp_program->GetSessionMappingMap();
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
// Pipeline Management - 3GPP TS 29.244 Section 5.2
//------------------------------------------------------------------------------
/**
 * @brief Create BPF pipeline for a new PFCP session
 *
 * Processes all PDRs in the session and configures BPF maps for packet
 * processing. This includes:
 * - Validating PDR count against system limits
 * - Extracting PDI (Packet Detection Information) from each PDR
 * - Creating FAR (Forwarding Action Rules) and QER (QoS Enforcement Rules)
 * - Updating BPF maps for session lookup, PDR matching, and ARP resolution
 * - Launching async ARP table updates for N3/N6 interfaces
 *
 * @param session PFCP session containing PDRs, FARs, QERs
 * @throws std::runtime_error if PDR count exceeds MAX_PDRS_SESSION or
 *         mandatory IEs are missing
 *
 * 3GPP References:
 * - TS 29.244: PFCP session establishment
 * - TS 23.501 Section 5.8: User Plane function
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

    // Initialize PDR array for BPF map
    struct pfcp_pdr pdrs[MAX_PDRS_PER_PDU_SESSION_LIMIT] = {0};
    int pdr_index                                        = 0;

    // Get network configuration for ARP updates
    const uint32_t dn_ip     = upf_cfg.remote_n6.s_addr;
    const uint32_t upf_n3_ip = upf_cfg.n3.addr4.s_addr;
    const uint32_t upf_n6_ip = upf_cfg.n6.addr4.s_addr;

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
        logger.warn("UE IP address missing for PDR %u", pdr_id);
        // TODO: Implement IP allocation when UE IP is not provided
      }

      // Store PDU session mapping (UE IP -> TEID -> SEID)
      StorePduSessionInMap(
          upf_xdp_program, ue_ip_address.ipv4_address.s_addr, fteid.teid, 0,
          seid);

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

      // Create BPF structures
      struct pfcp_pdr bpf_pdr = ConvertPdr(pdr);
      struct pfcp_far bpf_far = ConvertFar(far);
      struct pfcp_qer bpf_qer = ConvertQer(qer);

      // For downlink PDRs, QFI is not in PDI (no incoming GTP-U
      // header) Copy QFI from QER into PDR's PDI for BPF matching logic See
      // 3GPP TS 29.244 Section 8.2.89 - QFI is in QER for downlink
      if (bpf_pdr.pdi.qfi.qfi == 0 && bpf_qer.qos_flow_identifier.qfi != 0) {
        bpf_pdr.pdi.qfi.qfi = bpf_qer.qos_flow_identifier.qfi;
      }

      // Update rules_match_pdr map (PDR ID + SEID -> FAR + QER)
      struct rules_match_pdr rules = {0};
      rules.far                    = bpf_far;
      rules.qer                    = bpf_qer;

      struct pdrs_per_session pdr_key = {0};
      pdr_key.pdr_id                  = pdr_id;
      pdr_key.seid                    = seid;

      auto rules_map = upf_xdp_program->GetMapByName("rules_match_pdr_map");
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
                      upf_cfg.n6.if_name.c_str(), mac.c_str(), seid);
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
              Logger::upf_app().error(
                  "1111111111111111111111111111111111111111111");
              std::string mac =
                  UpdateArpTableForN3(upf_xdp_program, gnb_ip, upf_n3_ip, seid);
              Logger::upf_app().debug(
                  "ARP: %s dev %s lladdr %s [SEID=%" PRIu64 "]", buf_gnb_ip,
                  upf_cfg.n3.if_name.c_str(), mac.c_str(), seid);
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
    // Store all PDRs in session map (batch update)
    auto session_pdrs_map =
        upf_xdp_program->GetMapByName("pdrs_per_session_map");
    if (session_pdrs_map) {
      session_pdrs_map->Update(seid, pdrs, BPF_ANY);
    }

    logger.info(
        "Pipeline created for session " SEID_FMT " with %d PDRs", seid,
        pdr_index);

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
 * Updates BPF maps to reflect session modifications. This includes:
 * - Validating PDR count against system limits
 * - Updating PDU session mapping (UE IP <-> TEIDs <-> SEID)
 * - Re-creating PDR/FAR/QER structures for all PDRs in session
 * - Updating BPF maps: session_pdrs, rules_match_pdr, sdf_filters
 * - Launching async ARP table updates for modified endpoints
 * - Enabling QoS enforcement if downlink QERs present
 *
 * @param session PFCP session containing updated PDRs, FARs, QERs
 * @param teid_ul DEPRECATED - not used (kept for backward compatibility)
 * @param teid_dl DEPRECATED - not used (kept for backward compatibility)
 * @throws std::runtime_error if PDR count exceeds limits, mandatory IEs
 * missing, or UE/gNB IP addresses not found
 *
 * 3GPP References:
 * - TS 29.244 Section 7.5.4: PFCP Session Modification
 * - TS 29.244 Section 8.2.9-11: Update PDR/FAR/QER
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

    // Get network configuration for ARP updates
    const uint32_t dn_ip     = upf_cfg.remote_n6.s_addr;
    const uint32_t upf_n3_ip = upf_cfg.n3.addr4.s_addr;
    const uint32_t upf_n6_ip = upf_cfg.n6.addr4.s_addr;

    // Get or create the sets for this session
    auto& n6_ips_updated = session_n6_arp_cache_[seid];
    auto& n3_ips_updated = session_n3_arp_cache_[seid];

    // Ethernet PDU sessions have no UE IP — route to dedicated handler
    if (session->get_pdn_type() == pfcp::pdn_type_value_e::ETHERNET) {
      logger.debug(
          "ETH-PDU: modifying pipeline for ETH PDU session " SEID_FMT, seid);

      // Extract primary UL/DL TEIDs from session PDRs/FARs
      uint32_t primary_teid_ul = 0, primary_teid_dl = 0;
      for (const auto& pdr : session->pdrs_uplink) {
        primary_teid_ul = SessionManager::GetUplinkTeidFromPdr(pdr);
        if (primary_teid_ul) break;
      }
      for (const auto& pdr : session->pdrs_downlink) {
        std::shared_ptr<pfcp::pfcp_far> far;
        if (GetFarForPdr(session, pdr, far)) {
          primary_teid_dl = SessionManager::GetDownlinkTeidFromFar(far);
          if (primary_teid_dl) break;
        }
      }

      // Use gNB IP so broadcast_callback_fn sets correct iph->daddr
      uint32_t gnb_ip = RetrieveGnbIp(session);
      storeETHPduSessionInMap(
          upf_xdp_program, primary_teid_ul, primary_teid_dl, gnb_ip, seid);

      // Update ETH-specific PDR and rules maps
      struct pfcp_pdr eth_pdrs[MAX_PDRS_PER_PDU_SESSION_LIMIT] = {0};
      int eth_pdr_index                                        = 0;

      for (const auto& pdr : session->pdrs) {
        uint16_t pdr_id = pdr->pdr_id.rule_id;
        std::shared_ptr<pfcp::pfcp_far> far;
        if (!GetFarForPdr(session, pdr, far)) {
          throw std::runtime_error(
              "ETH-PDU: FAR not found for PDR " + std::to_string(pdr_id));
        }
        std::shared_ptr<pfcp::pfcp_qer> qer = nullptr;
        GetQerForPdr(session, pdr, qer);

        struct rules_match_pdr rules = {0};
        rules.far                    = ConvertFar(far);
        rules.qer                    = ConvertQer(qer);

        struct pdrs_per_session pdr_key = {0};
        pdr_key.pdr_id                  = pdr_id;
        pdr_key.seid                    = seid;

        auto eth_rules_map =
            upf_xdp_program->GetMapByName("m_eth__rules_match_pdr");
        if (eth_rules_map) {
          eth_rules_map->Update(pdr_key, rules, BPF_ANY);
        }

        eth_pdrs[eth_pdr_index++] = ConvertPdr(pdr);
      }

      auto eth_pdrs_map = upf_xdp_program->GetMapByName("m_eth__session_pdrs");
      if (eth_pdrs_map) {
        eth_pdrs_map->Update(seid, eth_pdrs, BPF_ANY);
      }

      logger.info(
          "ETH-PDU: Pipeline modified for session " SEID_FMT " with %d PDRs",
          seid, eth_pdr_index);
      return;
    }

    // A modification may legitimately leave the session with no PDRs (every
    // rule removed and none re-created). That is a clean teardown of the data
    // plane for this session, not an error: clear its map entries and return
    // instead of throwing "Missing UE IP" below.
    if (session->pdrs.empty()) {
      logger.info(
          "Session " SEID_FMT
          " has no PDRs after modification - clearing data plane",
          seid);
      ClearSessionRuleEntries(upf_xdp_program, seid);
      struct pfcp_pdr empty_pdrs[MAX_PDRS_PER_PDU_SESSION_LIMIT] = {0};
      auto session_pdrs_map = upf_xdp_program->GetSessionPdrsMap();
      if (session_pdrs_map) {
        session_pdrs_map->Update(seid, empty_pdrs, BPF_ANY);
      }
      auto enabled_qos_map = upf_xdp_program->GetQosEnablingMap();
      if (enabled_qos_map) {
        try {
          enabled_qos_map->Remove(seid);
        } catch (...) {
        }
      }
      std::lock_guard<std::mutex> lock(mutex_);
      auto it = qer_programs_map_.find(seid);
      if (it != qer_programs_map_.end()) {
        it->second->TearDown();
        qer_programs_map_.erase(it);
      }
      return;
    }

    // Retrieve UE and gNB IPs (mandatory for non-ETH modification)
    uint32_t ue_ip = RetrieveUeIp(session);
    if (!ue_ip) {
      logger.error(
          "Missing UE IP Address. Handling this case not implemented yet!");
      throw std::runtime_error(
          "Missing UE IP Address in session " + std::to_string(seid));
    }

    uint32_t gnb_ip = RetrieveGnbIp(session);
    if (!gnb_ip) {
      logger.error("Missing gNB IP. Handling this case not implemented yet!");
      throw std::runtime_error(
          "Missing gNB IP in session " + std::to_string(seid));
    }

    // Check for QoS enforcement
    bool has_downlink_qer                = !session->qers_downlink.empty();
    const bool ebpf_acceleration_enabled = upf_cfg.enable_bpf_datapath;
    const bool qos_enforcement_enabled =
        ebpf_acceleration_enabled && upf_cfg.enable_qos;

    auto enabled_qos_map = upf_xdp_program->GetQosEnablingMap();
    if (qos_enforcement_enabled && has_downlink_qer) {
      uint32_t value = 1;
      if (enabled_qos_map) {
        enabled_qos_map->Update(seid, value, BPF_ANY);
      }

      // Tear down any pre-existing QER program for this session before
      // building a new one. Otherwise the old program's BPF skeleton and TC
      // attachments leak on every modification (the destructor does NOT call
      // TearDown), and the kernel accumulates stale TC filters.
      {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = qer_programs_map_.find(seid);
        if (it != qer_programs_map_.end()) {
          logger.debug(
              "Tearing down previous QER program for seid " SEID_FMT, seid);
          it->second->TearDown();
          qer_programs_map_.erase(it);
        }
      }

      logger.debug("Instantiate a new QER Program on Downlink");
      std::shared_ptr<QERProgram> qer_program =
          std::make_shared<QERProgram>(upf_cfg);
      qer_program->Setup(seid, session->qers_downlink, session->pdrs_downlink);

      {
        std::lock_guard<std::mutex> lock(mutex_);
        qer_programs_map_[seid] = qer_program;
      }
    } else {
      // QoS no longer applies to this session (e.g. all downlink QERs were
      // removed by a modification). Clear the enable flag so the data plane
      // stops diverting downlink packets into a TC/QoS path that is no longer
      // configured, and tear down any lingering QER program.
      if (enabled_qos_map) {
        try {
          enabled_qos_map->Remove(seid);
        } catch (...) {
        }
      }
      std::lock_guard<std::mutex> lock(mutex_);
      auto it = qer_programs_map_.find(seid);
      if (it != qer_programs_map_.end()) {
        logger.debug(
            "Removing QER program for seid " SEID_FMT " (QoS disabled)", seid);
        it->second->TearDown();
        qer_programs_map_.erase(it);
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

      StorePduSessionInMap(
          upf_xdp_program, ue_ip, primary_teid_ul, primary_teid_dl, seid);

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

    // Drop stale per-rule map entries (PDRs/QFIs that a previous version of
    // this session had but that are no longer present) before re-populating.
    // rules_match_pdr_map and sdf_filters_map are keyed by rule/QFI, so unlike
    // pdrs_per_session_map (a per-seid array that is fully overwritten) they
    // would otherwise accumulate dead entries across modifications.
    ClearSessionRuleEntries(upf_xdp_program, seid);

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

      // Create BPF structures
      struct pfcp_pdr bpf_pdr = ConvertPdr(pdr);
      struct pfcp_far bpf_far = ConvertFar(far);
      struct pfcp_qer bpf_qer = ConvertQer(qer);

      // CRITICAL: For downlink PDRs, QFI is not in PDI (no incoming GTP-U
      // header) Copy QFI from QER into PDR's PDI for BPF matching logic See
      // 3GPP TS 29.244 Section 8.2.89 - QFI is in QER for downlink
      if (bpf_pdr.pdi.qfi.qfi == 0 && bpf_qer.qos_flow_identifier.qfi != 0) {
        bpf_pdr.pdi.qfi.qfi = bpf_qer.qos_flow_identifier.qfi;
      }

      // Update rules_match_pdr map (PDR ID + SEID -> FAR + QER)
      struct rules_match_pdr rules = {0};
      rules.far                    = bpf_far;
      rules.qer                    = bpf_qer;

      struct pdrs_per_session pdr_key = {0};
      pdr_key.pdr_id                  = pdr_id;
      pdr_key.seid                    = seid;

      auto rules_map = upf_xdp_program->GetRulesMatchPdrMap();
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
                    upf_cfg.n6.if_name.c_str(), mac.c_str(), seid);
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
                    upf_cfg.n3.if_name.c_str(), mac.c_str(), seid);
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
    auto session_pdrs_map = upf_xdp_program->GetSessionPdrsMap();
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
void SessionProgramManager::storeETHPduSessionInMap(
    std::shared_ptr<UPF_XDPProgram> pUPF_XDPProgram, uint32_t teid_ul,
    uint32_t teid_dl, uint32_t n3IpAddress, uint64_t seid) {
  auto eth_session_map =
      pUPF_XDPProgram->GetMapByName("m_eth__session_mapping");
  if (!eth_session_map) {
    Logger::upf_app().error(
        "ETH-PDU: m_eth__session_mapping BPF map not found");
    return;
  }

  if (likely(IsLittleEndian())) {
    teid_ul     = htonl(teid_ul);
    teid_dl     = htonl(teid_dl);
    n3IpAddress = htole32(n3IpAddress);
  }

  struct eth__session_id eth_session = {0};
  uint32_t key                       = teid_ul;

  const bool exists = (eth_session_map->Lookup(key, &eth_session) == 0);
  if (exists) {
    if (eth_session.teid_ul == 0)
      eth_session.teid_ul = (teid_ul != 0 ? teid_ul : teid_dl);
    if (eth_session.teid_dl == 0)
      eth_session.teid_dl = (teid_dl != 0 ? teid_dl : teid_ul);
  } else {
    eth_session.teid_ul      = teid_ul;
    eth_session.teid_dl      = teid_dl;
    eth_session.ipv4_address = n3IpAddress;
    eth_session.seid         = seid;
  }
  eth_session_map->Update(key, eth_session, BPF_ANY);
  Logger::upf_app().debug(
      "ETH-PDU: Stored session map TEID_UL=%u TEID_DL=%u SEID=%" PRIu64,
      teid_ul, teid_dl, seid);
}

//------------------------------------------------------------------------------
void SessionProgramManager::RemoveETHPduSessionFromMaps(
    std::shared_ptr<UPF_XDPProgram> xdp_program, uint64_t seid) {
  if (!xdp_program) return;

  // --- m_eth__session_mapping (key: uint32_t teid_ul) ---
  // Collect matching keys and DL TEIDs, then delete.
  std::vector<uint32_t> teid_keys;
  std::vector<uint32_t> dl_teids;
  auto eth_session_map = xdp_program->GetMapByName("m_eth__session_mapping");
  if (eth_session_map) {
    uint32_t key = 0, next;
    while (eth_session_map->GetNextKey(key, next) == 0) {
      struct eth__session_id val = {};
      if (eth_session_map->Lookup(next, &val) == 0 && val.seid == seid) {
        teid_keys.push_back(next);
        dl_teids.push_back(val.teid_dl);
      }
      key = next;
    }
    for (auto& k : teid_keys) {
      try {
        eth_session_map->Remove(k);
      } catch (...) {
      }
    }
    Logger::upf_app().debug(
        "ETH-PDU: removed %zu m_eth__session_mapping entries for seid %" PRIu64,
        teid_keys.size(), seid);
  }

  // --- m_eth__session_pdrs (key: uint64_t seid) ---
  auto eth_pdrs_map = xdp_program->GetMapByName("m_eth__session_pdrs");
  if (eth_pdrs_map) {
    try {
      eth_pdrs_map->Remove(seid);
    } catch (...) {
    }
  }

  // --- m_eth__rules_match_pdr (key: struct pdrs_per_session {pdr_id, seid})
  // ---
  auto eth_rules_map = xdp_program->GetMapByName("m_eth__rules_match_pdr");
  if (eth_rules_map) {
    std::vector<struct pdrs_per_session> rule_keys;
    struct pdrs_per_session key = {0, 0}, next;
    while (eth_rules_map->GetNextKey(key, next) == 0) {
      if (next.seid == seid) rule_keys.push_back(next);
      key = next;
    }
    for (auto& k : rule_keys) {
      try {
        eth_rules_map->Remove(k);
      } catch (...) {
      }
    }
    Logger::upf_app().debug(
        "ETH-PDU: removed %zu m_eth__rules_match_pdr entries for seid %" PRIu64,
        rule_keys.size(), seid);
  }

  // --- m_mac_pdu_session (key: uint8_t[6] MAC) ---
  // Delete entries whose DL TEID matches this session.
  auto mac_map = xdp_program->GetMapByName("m_mac_pdu_session");
  if (mac_map && !dl_teids.empty()) {
    std::set<uint32_t> dl_teid_set(dl_teids.begin(), dl_teids.end());
    std::vector<std::array<uint8_t, ETH_ALEN>> mac_keys;
    std::array<uint8_t, ETH_ALEN> key = {}, next;
    while (mac_map->GetNextKey(key, next) == 0) {
      struct mac_pdu_session_value val = {};
      if (mac_map->Lookup(next, &val) == 0 && dl_teid_set.count(val.teid)) {
        mac_keys.push_back(next);
      }
      key = next;
    }
    for (auto& k : mac_keys) {
      try {
        mac_map->Remove(k);
      } catch (...) {
      }
    }
    Logger::upf_app().debug(
        "ETH-PDU: removed %zu m_mac_pdu_session entries for seid %" PRIu64,
        mac_keys.size(), seid);
  }
}

//------------------------------------------------------------------------------
void SessionProgramManager::ClearAllETHPduMaps(
    std::shared_ptr<UPF_XDPProgram> xdp_program) {
  if (!xdp_program) return;

  auto delete_all_uint32 = [](std::shared_ptr<BPFMap> map, const char* label) {
    if (!map) return;
    std::vector<uint32_t> keys;
    uint32_t key = 0, next;
    while (map->GetNextKey(key, next) == 0) {
      keys.push_back(next);
      key = next;
    }
    for (auto& k : keys) {
      try {
        map->Remove(k);
      } catch (...) {
      }
    }
    Logger::upf_app().debug(
        "ETH-PDU: cleared %zu entries from %s", keys.size(), label);
  };

  auto delete_all_uint64 = [](std::shared_ptr<BPFMap> map, const char* label) {
    if (!map) return;
    std::vector<uint64_t> keys;
    uint64_t key = 0, next;
    while (map->GetNextKey(key, next) == 0) {
      keys.push_back(next);
      key = next;
    }
    for (auto& k : keys) {
      try {
        map->Remove(k);
      } catch (...) {
      }
    }
    Logger::upf_app().debug(
        "ETH-PDU: cleared %zu entries from %s", keys.size(), label);
  };

  auto delete_all_pdr_key = [](std::shared_ptr<BPFMap> map, const char* label) {
    if (!map) return;
    std::vector<struct pdrs_per_session> keys;
    struct pdrs_per_session key = {0, 0}, next;
    while (map->GetNextKey(key, next) == 0) {
      keys.push_back(next);
      key = next;
    }
    for (auto& k : keys) {
      try {
        map->Remove(k);
      } catch (...) {
      }
    }
    Logger::upf_app().debug(
        "ETH-PDU: cleared %zu entries from %s", keys.size(), label);
  };

  auto delete_all_mac = [](std::shared_ptr<BPFMap> map, const char* label) {
    if (!map) return;
    std::vector<std::array<uint8_t, ETH_ALEN>> keys;
    std::array<uint8_t, ETH_ALEN> key = {}, next;
    while (map->GetNextKey(key, next) == 0) {
      keys.push_back(next);
      key = next;
    }
    for (auto& k : keys) {
      try {
        map->Remove(k);
      } catch (...) {
      }
    }
    Logger::upf_app().debug(
        "ETH-PDU: cleared %zu entries from %s", keys.size(), label);
  };

  delete_all_uint32(
      xdp_program->GetMapByName("m_eth__session_mapping"),
      "m_eth__session_mapping");
  delete_all_uint64(
      xdp_program->GetMapByName("m_eth__session_pdrs"), "m_eth__session_pdrs");
  delete_all_pdr_key(
      xdp_program->GetMapByName("m_eth__rules_match_pdr"),
      "m_eth__rules_match_pdr");
  delete_all_mac(
      xdp_program->GetMapByName("m_mac_pdu_session"), "m_mac_pdu_session");
}

//------------------------------------------------------------------------------
void SessionProgramManager::ClearSessionRuleEntries(
    std::shared_ptr<UPF_XDPProgram> xdp_program, uint64_t seid) {
  if (!xdp_program) return;

  // --- rules_match_pdr_map (key: struct pdrs_per_session {pdr_id, seid}) ---
  auto rules_map = xdp_program->GetRulesMatchPdrMap();
  if (rules_map) {
    std::vector<struct pdrs_per_session> keys;
    struct pdrs_per_session key = {0, 0}, next;
    while (rules_map->GetNextKey(key, next) == 0) {
      if (next.seid == seid) keys.push_back(next);
      key = next;
    }
    for (auto& k : keys) {
      try {
        rules_map->Remove(k);
      } catch (...) {
      }
    }
    if (!keys.empty()) {
      Logger::upf_app().debug(
          "Cleared %zu stale rules_match_pdr entries for seid " SEID_FMT,
          keys.size(), seid);
    }
  }

  // --- sdf_filters_map (key: struct session_qfi {seid, qfi}) ---
  auto sdf_map = xdp_program->GetSdfFilterMap();
  if (sdf_map) {
    std::vector<struct session_qfi> keys;
    struct session_qfi key = {0}, next;
    while (sdf_map->GetNextKey(key, next) == 0) {
      if (next.seid == seid) keys.push_back(next);
      key = next;
    }
    for (auto& k : keys) {
      try {
        sdf_map->Remove(k);
      } catch (...) {
      }
    }
    if (!keys.empty()) {
      Logger::upf_app().debug(
          "Cleared %zu stale sdf_filters entries for seid " SEID_FMT,
          keys.size(), seid);
    }
  }
}

//------------------------------------------------------------------------------
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

// 3GPP TS 29.244 Section 8.2.3 - FAR Conversion
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
// 3GPP TS 29.244 Section 8.2.2 - PDR Conversion
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
  bpf_pdr.urr_id.urr_id = pdr->urr_id.second.urr_id;

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

  if (pdr->activate_predefined_rules.first) {
    memcpy(
        &bpf_pdr.activate_predefined_rules, &pdr->activate_predefined_rules,
        sizeof(struct activate_predefined_rules));
  }

  if (pdr->outer_header_removal.first) {
    memcpy(
        &bpf_pdr.outer_header_removal, &pdr->outer_header_removal,
        sizeof(struct outer_header_removal));
  }

  return bpf_pdr;
}

//------------------------------------------------------------------------------
// 3GPP TS 29.244 Section 8.2.4 - QER Conversion
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

  if (qer->qer_correlation_id.first) {
    bpf_qer.qer_correlation_id.qer_correlation_id =
        qer->qer_correlation_id.second.qer_correlation_id;
  }

  if (qer->reflective_qos.first) {
    bpf_qer.reflective_qos.rqi = qer->reflective_qos.second.rqi;
  }

  return bpf_qer;
}

//------------------------------------------------------------------------------
// ARP Table Management - RFC 826
//------------------------------------------------------------------------------

// // 3GPP TS 23.501 Section 5.8.2.3 - N6 Interface
// void SessionProgramManager::UpdateArpTableForN6(
//     std::shared_ptr<UPF_XDPProgram> xdp_program, uint32_t dn_ip,
//     uint32_t upf_n6_ip) {
//   if (!xdp_program) {
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
//     // xdp_program->GetArpTableMap()->Update(upf_n6_ip, entry, BPF_ANY);
//     auto arp_table_map = xdp_program->GetMapByName("arp_table_map");
//     if (arp_table_map) {
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

// 3GPP TS 23.501 Section 5.8.2.3 - N6 Interface
std::string SessionProgramManager::UpdateArpTableForN6(
    std::shared_ptr<UPF_XDPProgram> xdp_program, uint32_t dn_ip,
    uint32_t upf_n6_ip) {
  if (!xdp_program) {
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
    auto arp_table_map = xdp_program->GetMapByName("arp_table_map");
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
// 3GPP TS 23.501 Section 5.8.2.2 - N3 Interface
std::string SessionProgramManager::UpdateArpTableForN3(
    std::shared_ptr<UPF_XDPProgram> xdp_program, uint32_t gnb_ip,
    uint32_t upf_n3_ip, uint64_t seid) {
  if (!xdp_program) {
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

    /*
     * Bug fix: the key must be the peer IP (gNB),
     * not the UPF's local IP.
     * Otherwise every session overwrites the same entry.
     *
     */
    uint32_t arp_key = ip_for_mac_lookup;  // = gNB IP in kernel byte order

    // Update ARP table in BPF map
    auto arp_table_map = xdp_program->GetMapByName("arp_table_map");
    if (arp_table_map) {
      arp_table_map->Update(arp_key, entry, BPF_ANY);
    }

    for (auto it = pfcp_programs->begin(); it != pfcp_programs->end(); ++it) {
      uint64_t savedSeid                          = it->seid;
      std::shared_ptr<UPF_XDPProgram> xdp_program = it->xdp_program;

      if (savedSeid == seid) {
        auto arp_table_map = xdp_program->GetMapByName("arp_table_map");
        if (arp_table_map) {
          arp_table_map->Update(arp_key, entry, BPF_ANY);
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

void SessionProgramManager::AddPfcpProgram(
    uint64_t seid, std::shared_ptr<UPF_XDPProgram> xdp_program) {
  // std::lock_guard<std::mutex> lock(mutex_);

  PfcpProgramInfo pfcp_prgm;
  pfcp_prgm.seid        = seid;
  pfcp_prgm.xdp_program = xdp_program;

  pfcp_programs->push_back(pfcp_prgm);
}

//------------------------------------------------------------------------------
std::shared_ptr<SessionPrograms> SessionProgramManager::FindSessionPrograms(
    uint64_t seid) const {
  // std::lock_guard<std::mutex> lock(mutex_);

  auto it = session_programs_map_.find(seid);
  return (it != session_programs_map_.end()) ? it->second : nullptr;
}

//------------------------------------------------------------------------------
// 3GPP TS 29.244 Section 8.2.74 - Get gNodeB IP from Outer Header Creation
uint32_t SessionProgramManager::GetGnodebIp(
    std::shared_ptr<pfcp::pfcp_far> far) const {
  if (!far) return 0;

  pfcp::forwarding_parameters forward_param;

  if (!far->get(forward_param)) {
    Logger::upf_app().error(
        "Could not retrieve the forwarding parameters from FAR");
    throw std::runtime_error("gNodeB IP cannot be retrieved");
  }

  if ((forward_param.outer_header_creation.first)) {
    return far->forwarding_parameters.second.outer_header_creation.second
        .ipv4_address.s_addr;
  }

  return 0;
}

//------------------------------------------------------------------------------
uint32_t SessionProgramManager::RetrieveGnbIp(
    std::shared_ptr<pfcp::pfcp_session> session) const {
  if (!session) return 0;

  pfcp::forwarding_parameters forward_param;
  for (const auto& far : session->fars) {
    if (!far->get(forward_param)) {
      continue;
    }

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
uint32_t SessionProgramManager::RetrieveUeIp(
    std::shared_ptr<pfcp::pfcp_session> session) const {
  if (!session) return 0;

  pfcp::pdi pdi;
  pfcp::ue_ip_address_t ue_ip_address;

  for (const auto& pdr : session->pdrs) {
    if ((pdr->get(pdi)) && (pdi.get(ue_ip_address))) {
      return ue_ip_address.ipv4_address.s_addr;
    }
  }

  return 0;
}

//------------------------------------------------------------------------------
bool SessionProgramManager::GetFarForPdr(
    std::shared_ptr<pfcp::pfcp_session> session,
    std::shared_ptr<pfcp::pfcp_pdr> pdr,
    std::shared_ptr<pfcp::pfcp_far>& out_far) const {
  pfcp::far_id_t far_id;
  return (pdr->get(far_id) && session->get(far_id.far_id, out_far));
}

//------------------------------------------------------------------------------
bool SessionProgramManager::GetQerForPdr(
    std::shared_ptr<pfcp::pfcp_session> session,
    std::shared_ptr<pfcp::pfcp_pdr> pdr,
    std::shared_ptr<pfcp::pfcp_qer>& out_qer) const {
  pfcp::qer_id_t qer_id;
  return (pdr->get(qer_id) && session->get(qer_id.qer_id, out_qer));
}

//------------------------------------------------------------------------------
// Observer Pattern
//------------------------------------------------------------------------------

void SessionProgramManager::SetSessionObserver(ISessionObserver* observer) {
  // std::lock_guard<std::mutex> lock(mutex_);
  session_observer_ = observer;
  Logger::upf_app().debug("Session observer set");
}

//------------------------------------------------------------------------------
// Internal Methods
//------------------------------------------------------------------------------

int32_t SessionProgramManager::GetEmptySlot() {
  for (size_t i = 0; i < program_array_.size(); ++i) {
    if (program_array_[i] == kEmptySlot) {
      return static_cast<int32_t>(i);
    }
  }
  return -1;
}
