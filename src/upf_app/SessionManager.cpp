#include "SessionManager.h"
//#include <pfcp_session_pdr_lookup_xdp_user.h>
#include <SessionProgramManager.h>
#include <pfcp_session_lookup_xdp_user.h>
#include <bits/stdc++.h>  //sort
#include <interfaces/SessionBpf.h>
#include <pfcp/pfcp_session.h>
#include <wrappers/BPFMaps.h>
#include "logger.hpp"

#include <next_prog_rule_key.h>

#include "upf_config.hpp"

using namespace oai::config;
extern upf_config upf_cfg;

//---------------------------------------------------------------------------------------------------------------
enum class Direction { Uplink, Downlink };

//---------------------------------------------------------------------------------------------------------------
SessionManager::SessionManager() {}

//---------------------------------------------------------------------------------------------------------------
SessionManager::~SessionManager() {}

//---------------------------------------------------------------------------------------------------------------
// Helper function to extract PDI
bool SessionManager::extractPdi(
    std::shared_ptr<pfcp::pfcp_pdr> pdr, pfcp::pdi& pdi) {
  return (pdr->get(pdi));
}

//---------------------------------------------------------------------------------------------------------------
// Helper function to extract source interface
bool SessionManager::extractSourceIface(
    pfcp::pdi& pdi, pfcp::source_interface_t& sourceInterface) {
  return (pdi.get(sourceInterface));
}

//---------------------------------------------------------------------------------------------------------------
// Helper function to extract source interface
bool SessionManager::extractUeIpv4(
    pfcp::pdi& pdi, pfcp::ue_ip_address_t& ueIpAddress) {
  return (pdi.get(ueIpAddress));
}

//---------------------------------------------------------------------------------------------------------------
// Helper function to extract FAR
bool SessionManager::extractFar(
    std::shared_ptr<pfcp::pfcp_pdr> pdr,
    std::shared_ptr<pfcp::pfcp_session> session,
    std::shared_ptr<pfcp::pfcp_far>& outFar) {
  pfcp::far_id_t farId;
  return (pdr->get(farId) && session->get(farId.far_id, outFar));
}

//---------------------------------------------------------------------------------------------------------------
// Helper function to extract Forwarding Parameters
bool SessionManager::extractForwardingParams(
    std::shared_ptr<pfcp::pfcp_far> far,
    pfcp::forwarding_parameters& forwardingParams) {
  return far->get(forwardingParams);
}

//---------------------------------------------------------------------------------------------------------------
// Helper function to find the Uplink TEID to update
uint64_t SessionManager::findUplinkTeid(
    uint64_t seid,
    const std::vector<std::shared_ptr<pfcp::pfcp_session>>& sessions) {
  for (const auto& session : sessions) {
    if (session->get_up_seid() != seid) {
      continue;  // Skip to the next session if not matching seid
    }

    for (const auto& pdr : session->pdrs) {
      pfcp::pdi pdi;
      if (pdr->get(pdi)) {
        pfcp::source_interface_t sourceInterface;
        if (pdi.get(sourceInterface) &&
            sourceInterface.interface_value == INTERFACE_VALUE_ACCESS) {
          return session->teid_uplink.teid;
        }
      }
    }
  }

  return 0;  // Return 0 if teidToUpdate is not found
}

//---------------------------------------------------------------------------------------------------------------
void SessionManager::createBPFSession(
    std::shared_ptr<pfcp::pfcp_session> pSession_establishment,
    itti_n4_session_establishment_request* est_req,
    itti_n4_session_modification_request* mod_req,
    itti_n4_session_deletion_request* del_req) {
  auto& logger  = Logger::upf_n4();
  uint64_t seid = pSession_establishment->get_up_seid();

  sessions.push_back(pSession_establishment);

  logger.debug("Session %lu Received", seid);
  logger.debug("Preparing the Datapath ...");
  logger.debug("Find the PDR with Highest Precedence");

  // Process PDRs to populate uplink and downlink vectors
  processPDRs(pSession_establishment);

  auto& pdrs_uplink   = pSession_establishment->pdrs_uplink;
  auto& pdrs_downlink = pSession_establishment->pdrs_downlink;

  // Check if no PDRs were found for either direction
  if (pdrs_uplink.empty() && pdrs_downlink.empty()) {
    logger.error("No PDRs were found in session: %lu", seid);
    throw std::runtime_error("Session creation failed: No PDRs found.");
  }

  // Sort uplink and downlink PDRs by precedence
  sortPDRs(pdrs_uplink, pdrs_downlink);

  // Create BPF sessions for uplink and downlink directions
  if (!pdrs_uplink.empty()) {
    prepareEbpfSession(pSession_establishment, pdrs_uplink);
  }

  if (!pdrs_downlink.empty()) {
    prepareEbpfSession(pSession_establishment, pdrs_downlink);
  }

  // Store the session in the session map
  mSeidToSession[seid] = pSession_establishment;

  logger.debug("Session %lu successfully created and stored.", seid);
}

//---------------------------------------------------------------------------------------------------------------
void SessionManager::processPDRs(
    std::shared_ptr<pfcp::pfcp_session> pSession_establishment) {
  // PDR-specific containers
  std::vector<std::shared_ptr<pfcp::pfcp_pdr>> pdrs_uplink, pdrs_downlink;

  // QoS-specific containers
  std::vector<std::shared_ptr<pfcp::pfcp_qer>> qers_uplink, qers_downlink;
  const bool is_qos_enabled = upf_cfg.enable_bpf_datapath && upf_cfg.enable_qos;

  // Helper function to find QER by ID
  auto find_qer_by_id =
      [&](uint64_t qer_id) -> std::shared_ptr<pfcp::pfcp_qer> {
    for (auto& qer : pSession_establishment->qers) {
      if (qer->qer_id.second.qer_id == qer_id) {
        return qer;
      }
    }
    Logger::upf_n4().debug("QER not found for ID: " + std::to_string(qer_id));
    return nullptr;
  };

  // Process each PDR
  for (auto& pdr : pSession_establishment->pdrs) {
    // Extract PDI and Source Interface
    pfcp::pdi pdi;
    pfcp::source_interface_t sourceInterface;
    if (!(pdr->get(pdi) && pdi.get(sourceInterface))) {
      throw std::runtime_error(
          "Missing Mandatory IE (PDI or Source Interface) within PDR: " +
          std::to_string(pdr->pdr_id.rule_id));
    }

    // Handle QoS if enabled
    std::shared_ptr<pfcp::pfcp_qer> qer = nullptr;
    if (is_qos_enabled && pdr->qer_id.second.qer_id) {
      qer = find_qer_by_id(pdr->qer_id.second.qer_id);
    }

    // Categorize PDRs based on the source interface
    switch (sourceInterface.interface_value) {
      case INTERFACE_VALUE_ACCESS:
        pdrs_uplink.push_back(pdr);
        if (is_qos_enabled && qer) qers_uplink.push_back(qer);
        break;

      case INTERFACE_VALUE_CORE:
        pdrs_downlink.push_back(pdr);
        if (is_qos_enabled && qer) qers_downlink.push_back(qer);
        break;

      case INTERFACE_VALUE_SGI_LAN_N6_LAN:
      case INTERFACE_VALUE_CP_FUNCTION:
      case INTERFACE_VALUE_LI_FUNCTION:
        Logger::upf_n4().info(
            "Unhandled source interface for PDR: " +
            std::to_string(pdr->pdr_id.rule_id));
        break;

      default:
        Logger::upf_n4().warn(
            "Unknown source interface value: " +
            std::to_string(sourceInterface.interface_value));
        break;
    }
  }

  pSession_establishment->pdrs_uplink   = pdrs_uplink;
  pSession_establishment->pdrs_downlink = pdrs_downlink;

  // Save QoS results back if enabled
  if (is_qos_enabled) {
    pSession_establishment->qers_uplink   = qers_uplink;
    pSession_establishment->qers_downlink = qers_downlink;
  }
}

//---------------------------------------------------------------------------------------------------------------
void SessionManager::sortPDRs(
    std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs_uplink,
    std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs_downlink) {
  // Sort uplink and downlink vectors
  std::sort(pdrs_uplink.begin(), pdrs_uplink.end(), comparePDR);
  std::sort(pdrs_downlink.begin(), pdrs_downlink.end(), comparePDR);
}

//---------------------------------------------------------------------------------------------------------------
void SessionManager::prepareEbpfSession(
    std::shared_ptr<pfcp::pfcp_session> pSession_establishment,
    std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs) {
  auto& logger = Logger::upf_app();

  // Exit early if no PDRs exist
  if (pdrs.empty()) {
    logger.warn("NO PDR is available to create a PDU Session");
    return;
  }

  // Retrieve the highest precedence PDR
  auto pdrHighPrecedence = pdrs.front();

  pfcp::pdi pdi;
  pfcp::source_interface_t sourceInterface;
  if (!(pdrHighPrecedence->get(pdi) && pdi.get(sourceInterface))) {
    throw std::runtime_error(
        "Missing Mandatory IE (PDI or Source Interface) within PDR: " +
        std::to_string(pdrHighPrecedence->pdr_id.rule_id));
  }

  logger.debug(
      "The PDR %d has the Highest Precedence",
      pdrHighPrecedence->pdr_id.rule_id);

  processPDRDetails(pSession_establishment, pdrHighPrecedence);
}

//---------------------------------------------------------------------------------------------------------------
void SessionManager::processPDRDetails(
    std::shared_ptr<pfcp::pfcp_session> pSession,
    std::shared_ptr<pfcp::pfcp_pdr> pdrHighPrecedence) {
  auto& logger              = Logger::upf_app();
  const bool is_qos_enabled = upf_cfg.enable_bpf_datapath && upf_cfg.enable_qos;

  pfcp::pdi pdi;
  pfcp::fteid_t fteid;
  pfcp::ue_ip_address_t ueIpAddress;
  pfcp::source_interface_t sourceInterface;
  uint16_t pdr_id = pdrHighPrecedence->pdr_id.rule_id;

  if (!(pdrHighPrecedence->get(pdi) && pdi.get(sourceInterface))) {
    throw std::runtime_error(
        "Missing Mandatory IE (PDI or Source Interface) within PDR: " +
        std::to_string(pdr_id));
  }

  Direction direction;
  int interfaceValue = sourceInterface.interface_value;

  switch (interfaceValue) {
    case INTERFACE_VALUE_CORE: {
      direction = Direction::Uplink;
      logger.debug(
          "Create the eBPF Uplink Datapath for Session %lu",
          pSession->get_up_seid());
      break;
    }

    case INTERFACE_VALUE_ACCESS: {
      direction = Direction::Downlink;
      logger.debug(
          "Create the eBPF Downlink Datapath for Session %lu",
          pSession->get_up_seid());
      break;
    }

    default: {
      Logger::upf_app().warn("Unknown interface value: %d", interfaceValue);
      break;
    }
  }

  // Check for missing FTEID
  if (!pdi.get(fteid)) {
    fteid.teid = -1;

    logger.warn(
        "FTEID is missing for the current PDR. "
        "Note: This IE should not be present if the Traffic Endpoint ID is "
        "present. "
        "If the CHOOSE (CH) bit is set to 1, the UP function is expected to "
        "assign "
        "a local F-TEID to the PDR.");

    if (fteid.ch) {
      logger.debug("CHOOSE (CH) bit is set in FTEID.");
    } else {
      logger.debug("CHOOSE (CH) bit is not set in FTEID.");
    }
  }

  // Check for missing UE IP Address
  if (!pdi.get(ueIpAddress)) {
    ueIpAddress.ipv4_address.s_addr = 0;

    logger.warn(
        "UE IP Address is missing for the current PDR. "
        "Note: This IE should not be present if the Traffic Endpoint ID is "
        "present.");
  }

  // Log PDI extraction details
  logger.debug("PDI successfully extracted from PDR ID: %d.", pdr_id);
  logger.debug(
      "Extracting FAR from the highest precedence PDR ID: %d.", pdr_id);

  std::shared_ptr<pfcp::pfcp_far> pFar;

  if (!extractFar(pdrHighPrecedence, pSession, pFar)) {
    logger.error(
        "Failed to extract FAR IE from the highest precedence PDR with ID: %d.",
        pdr_id);

    throw std::runtime_error(
        "Error during FAR extraction: Unable to retrieve FAR IE for PDR ID: " +
        std::to_string(pdr_id) + ".");
  }

  std::vector<std::shared_ptr<pfcp::pfcp_qer>> pQer;
 
  /*
  * TODO: implement the QoS Enforcement on the uplink side

  if (is_qos_enabled) {
    pQer = (direction == Direction::Uplink) ? pSession->qers_uplink :
                                              std::vector<std::shared_ptr<pfcp::pfcp_qer>>{};
  }
  SessionProgramManager::getInstance().createPipeline(
      pSession->get_up_seid(), fteid.teid, interfaceValue,
      ueIpAddress.ipv4_address.s_addr, pFar, pQer, false, 0);
  */

  if (is_qos_enabled) {
    pQer = (direction == Direction::Downlink) ?
               pSession->qers_downlink :
               std::vector<std::shared_ptr<pfcp::pfcp_qer>>{};
  }
    
  SessionProgramManager::getInstance().createPipeline(
      pSession->get_up_seid(), fteid.teid, interfaceValue,
      ueIpAddress.ipv4_address.s_addr, pFar, pQer, false, 0);
}

//---------------------------------------------------------------------------------------------------------------
void SessionManager::updateBPFSession(
    std::shared_ptr<pfcp::pfcp_session> pSession,
    itti_n4_session_establishment_request* est_req,
    itti_n4_session_modification_request* mod_req,
    itti_n4_session_deletion_request* del_req) {
  Logger::upf_app().debug(
      "Session %d Will be updated", pSession->get_up_seid());

  if (!mod_req->pfcp_ies.create_pdrs.empty()) {
    // create_pdr& cr_pdr            = it;
    pfcp::fteid_t allocated_fteid = {};

    pfcp::far_id_t far_id = {};

    Logger::upf_app().debug("Find the PDR with Highest Precedence:");

    uint32_t pdrs_downlink_size = pSession->pdrs_downlink.size();
    uint32_t pdrs_uplink_size   = pSession->pdrs_uplink.size();

    for (int i = 0; i < pSession->pdrs.size(); i++) {
      pfcp::pdi pdi;
      pfcp::source_interface_t sourceInterface;
      pSession->pdrs[i]->get(pdi);
      pdi.get(sourceInterface);

      if (sourceInterface.interface_value == INTERFACE_VALUE_CORE) {
        pSession->pdrs_downlink.push_back(pSession->pdrs[i]);
      }

      if (sourceInterface.interface_value == INTERFACE_VALUE_ACCESS) {
        pSession->pdrs_uplink.push_back(pSession->pdrs[i]);
      }
    }

    if ((pSession->pdrs_uplink.empty()) && (pSession->pdrs_downlink.empty())) {
      Logger::upf_app().error("No PDR was found in session %d", pSession->seid);
      throw std::runtime_error("No PDR was found in session");
    }

    if (pdrs_downlink_size != pSession->pdrs_downlink.size()) {
      std::sort(
          pSession->pdrs_downlink.begin(), pSession->pdrs_downlink.end(),
          SessionManager::comparePDR);

      auto pdrHighPrecedenceDl = pSession->pdrs_downlink[0];
      Logger::upf_app().debug(
          "The Downlink PDR %d has the Highest Precedence",
          pdrHighPrecedenceDl->pdr_id.rule_id);

      Logger::upf_app().debug(
          "Extract PDI from the Downlink PDR %d",
          pdrHighPrecedenceDl->pdr_id.rule_id);

      updateBPFSessionDL(pSession, pdrHighPrecedenceDl);
    }

    if (pdrs_uplink_size != pSession->pdrs_uplink.size()) {
      std::sort(
          pSession->pdrs_uplink.begin(), pSession->pdrs_uplink.end(),
          SessionManager::comparePDR);

      auto pdrHighPrecedenceUl = pSession->pdrs_uplink[0];
      Logger::upf_app().debug(
          "The Uplink PDR %d has the Highest Precedence",
          pdrHighPrecedenceUl->pdr_id.rule_id);

      Logger::upf_app().debug(
          "Extract PDI from the Uplink PDR %d",
          pdrHighPrecedenceUl->pdr_id.rule_id);

      updateBPFSessionUL(pSession, pdrHighPrecedenceUl);
    }
  }

  for (auto it : mod_req->pfcp_ies.remove_pdrs) {
    Logger::upf_app().debug("Delete PDRs");
    Logger::upf_app().debug(
        "PDRs and FARs map entries are obsolete and need to be deleted");
  }
}

//---------------------------------------------------------------------------------------------------------------
void SessionManager::updateBPFSessionUL(
    std::shared_ptr<pfcp::pfcp_session> pSession,
    std::shared_ptr<pfcp::pfcp_pdr> pdrHighPrecedenceUl) {
  pfcp::pdi pdi;
  pfcp::fteid_t fteid;
  pfcp::ue_ip_address_t ueIpAddress;
  pfcp::source_interface_t sourceInterface;

  Logger::upf_app().debug(
      "Update the Uplink Direction Datapath For Session %d",
      pSession->get_up_seid());

  if (!(extractPdi(pdrHighPrecedenceUl, pdi) &&
        extractSourceIface(pdi, sourceInterface) &&
        extractUeIpv4(pdi, ueIpAddress))) {
    throw std::runtime_error("No fields available For Uplink Update PDI Check");
  }

  Logger::upf_app().debug(
      "PDI extracted from Uplink PDR %d", pdrHighPrecedenceUl->pdr_id.rule_id);

  Logger::upf_app().debug(
      "Extract Uplink FAR from the highest precedence Uplink PDR");

  std::shared_ptr<pfcp::pfcp_far> pFar;

  if (!extractFar(pdrHighPrecedenceUl, pSession, pFar)) {
    throw std::runtime_error("No fields available For Uplink Update FAR Check");
  }

  Logger::upf_app().info("Update Session For Uplink");
  Logger::upf_app().warn("TODO: update Uplink PDRs ...");
}

//---------------------------------------------------------------------------------------------------------------

// Function to update the Downlink Direction of a session
void SessionManager::updateBPFSessionDL(
    std::shared_ptr<pfcp::pfcp_session> pSession,
    std::shared_ptr<pfcp::pfcp_pdr> pdrHighPrecedenceDl) {
  uint64_t seidul = pSession->get_up_seid();
  pfcp::pdi pdi;
  pfcp::fteid_t fteid;
  pfcp::ue_ip_address_t ueIpAddress;
  pfcp::source_interface_t sourceInterface;

  if (!(extractPdi(pdrHighPrecedenceDl, pdi) &&
        extractSourceIface(pdi, sourceInterface) &&
        extractUeIpv4(pdi, ueIpAddress))) {
    throw std::runtime_error(
        "No fields available For Downlink Update PDI Check");
  }

  Logger::upf_app().debug(
      "Create the Downlink Direction Datapath for Session 0x%x", seidul);
  Logger::upf_app().debug(
      "PDI extracted from Downlink PDR %d",
      pdrHighPrecedenceDl->pdr_id.rule_id);
  Logger::upf_app().debug(
      "Extract FAR from the highest Precedence Downlink PDR");

  std::shared_ptr<pfcp::pfcp_far> pFar;

  if (!extractFar(pdrHighPrecedenceDl, pSession, pFar)) {
    throw std::runtime_error(
        "No fields available For Downlink Update FAR Check");
  }

  Logger::upf_app().debug("FAR ID %d", pFar->far_id.far_id);

  pfcp::forwarding_parameters forwardingParams;

  if (!extractForwardingParams(pFar, forwardingParams)) {
    Logger::upf_app().error(
        "Forwarding parameters were not found for Downlink Update");
  }

  fteid.teid       = forwardingParams.outer_header_creation.second.teid;
  uint64_t teid_ul = findUplinkTeid(seidul, sessions);

  // std::vector<std::shared_ptr<pfcp::pfcp_qer>> pQer =
  // pSession->qerIDsPerPDR.qers;
  // std::vector<std::shared_ptr<pfcp::pfcp_qer>> pQer = pSession->qers;

  if (teid_ul) {
    SessionProgramManager::getInstance().createPipeline(
        seidul, fteid.teid, INTERFACE_VALUE_CORE,
        ueIpAddress.ipv4_address.s_addr, pFar, pSession->qers, true, teid_ul);
  } else {
    Logger::upf_app().info("Uplink TEID not used for session: 0x%x", seidul);
    SessionProgramManager::getInstance().createPipeline(
        seidul, fteid.teid, INTERFACE_VALUE_CORE,
        ueIpAddress.ipv4_address.s_addr, pFar, pSession->qers, true, 0);
  }
}

//---------------------------------------------------------------------------------------------------------------
void SessionManager::removeBPFSession(
    std::shared_ptr<pfcp::pfcp_session> pSession,
    itti_n4_session_establishment_request* est_req,
    itti_n4_session_modification_request* mod_req,
    itti_n4_session_deletion_request* del_req) {
  uint64_t seid = pSession->get_up_seid();
  Logger::upf_app().info(
        "Session %lu will be deleted from Data-Path", seid);

  if (mSeidToSession.find(seid) == mSeidToSession.end()) {
    Logger::upf_app().error(
        "Session %d Does Not Exist. It Cannot be Removed", seid);
    // throw std::runtime_error("Session Does Not Exist. It Cannot be Removed");
  }

  SessionProgramManager::getInstance().removePipeline(seid);
  Logger::upf_app().debug("Session 0x%x Has Been Removed Successfully", seid);
}

//---------------------------------------------------------------------------------------------------------------
bool SessionManager::comparePDR(
    const std::shared_ptr<pfcp::pfcp_pdr>& pFirst,
    const std::shared_ptr<pfcp::pfcp_pdr>& pSecond) {
  pfcp::precedence_t precedenceFirst, precedenceSecond;
  // TODO: Check if exists.
  pFirst->get(precedenceFirst);
  pSecond->get(precedenceSecond);
  return precedenceFirst.precedence < precedenceSecond.precedence;
}

//---------------------------------------------------------------------------------------------------------------
void SessionManager::removeSession(uint64_t seid) {
  SessionProgramManager::getInstance().remove(seid);
  Logger::upf_app().debug("Session %d has been removed", seid);
}

//---------------------------------------------------------------------------------------------------------------
