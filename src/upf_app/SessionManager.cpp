#include "SessionManager.h"
#include <pfcp_session_pdr_lookup_xdp_user.h>
#include <SessionProgramManager.h>
#include <pfcp_session_lookup_xdp_user.h>
#include <bits/stdc++.h>  //sort
// #include <interfaces/ForwardingActionRules.h>
// #include <interfaces/PacketDetectionRules.h>

#include <interfaces/SessionBpf.h>
#include <pfcp/pfcp_session.h>
#include <wrappers/BPFMaps.h>
#include "logger.hpp"

#include <next_prog_rule_key.h>

#include "upf_config.hpp"

using namespace oai::config;
extern upf_config upf_cfg;

/*---------------------------------------------------------------------------------------------------------------*/
SessionManager::SessionManager() {}

/*---------------------------------------------------------------------------------------------------------------*/
SessionManager::~SessionManager() {}

/*****************************************************************************************************************/
// Helper function to extract PDI
bool SessionManager::extractPdi(
    std::shared_ptr<pfcp::pfcp_pdr> pdr, pfcp::pdi& pdi) {
  return (pdr->get(pdi));
}

/*****************************************************************************************************************/
// Helper function to extract source interface
bool SessionManager::extractSourceIface(
    pfcp::pdi& pdi, pfcp::source_interface_t& sourceInterface) {
  return (pdi.get(sourceInterface));
}

/*****************************************************************************************************************/
// Helper function to extract source interface
bool SessionManager::extractUeIpv4(
    pfcp::pdi& pdi, pfcp::ue_ip_address_t& ueIpAddress) {
  return (pdi.get(ueIpAddress));
}

/*---------------------------------------------------------------------------------------------------------------*/
// Helper function to extract FAR
bool SessionManager::extractFar(
    std::shared_ptr<pfcp::pfcp_pdr> pdr,
    std::shared_ptr<pfcp::pfcp_session> session,
    std::shared_ptr<pfcp::pfcp_far>& outFar) {
  pfcp::far_id_t farId;
  return (pdr->get(farId) && session->get(farId.far_id, outFar));
}

/*---------------------------------------------------------------------------------------------------------------*/
// Helper function to extract QER
// bool SessionManager::extractQer(
//     std::shared_ptr<pfcp::pfcp_pdr> pdr,
//     std::shared_ptr<pfcp::pfcp_session> session,
//     std::vector<std::shared_ptr<pfcp::pfcp_qer>>& outQer) {
//   //pfcp::qer_id_t qerId;
//   for (const auto& qerId : session->qerIDsPerPDR.qers) {
//   return (pdr->get(qerId) && session->get(qerId.qer_id, outQer));
//   }
// }

/*---------------------------------------------------------------------------------------------------------------*/
// Helper function to extract Forwarding Parameters
bool SessionManager::extractForwardingParams(
    std::shared_ptr<pfcp::pfcp_far> far,
    pfcp::forwarding_parameters& forwardingParams) {
  return far->get(forwardingParams);
}

/*---------------------------------------------------------------------------------------------------------------*/
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

/*---------------------------------------------------------------------------------------------------------------*/
void SessionManager::createSession(std::shared_ptr<SessionBpf> pSession) {
  SessionProgramManager::getInstance().create(pSession->getSeid());
  Logger::upf_app().debug(
      "Session %d Has Been Created Successfully", pSession->getSeid());
}

/*****************************************************************************************************************/
/*
 * Document: ETSI TS 129 244 V15.8.0 (2020-01)
 * PDI is a Mandatory IE within the Establishment request
 * Table 7.5.2.2-1: Create PDR IE within PFCP Session Establishment Request
 * Source Interface is the only Mandatory IE within PDI:
 * Table 7.5.2.2-2: PDI IE within PFCP Session Establishment Request
 */

// void SessionManager::createBPFSession(
//     std::shared_ptr<pfcp::pfcp_session> pSession_establishment,
//     itti_n4_session_establishment_request* est_req,
//     itti_n4_session_modification_request* mod_req,
//     itti_n4_session_deletion_request* del_req) {
//   auto& logger = Logger::upf_app();

//   uint64_t seid = pSession_establishment->get_up_seid();

//   logger.debug("Session %d Received", seid);
//   logger.debug("Preparing the Datapath ...");
//   logger.debug("Find the PDR with Highest Precedence");

//   auto& pdrs_uplink   = pSession_establishment->pdrs_uplink;
//   auto& pdrs_downlink = pSession_establishment->pdrs_downlink;

//   for (auto& pdr : pSession_establishment->pdrs) {
//     pfcp::pdi pdi;
//     pfcp::source_interface_t sourceInterface;
//     if (!(pdr->get(pdi) && pdi.get(sourceInterface))) {
//       throw std::runtime_error(
//           "Missing Mandatory IE (PDI or Source Interface) within PDR: " +
//           std::to_string(pdr->pdr_id.rule_id));
//     }

//     switch (sourceInterface.interface_value) {
//       case INTERFACE_VALUE_ACCESS:
//         pdrs_uplink.push_back(pdr);
//         break;
//       case INTERFACE_VALUE_CORE:
//         pdrs_downlink.push_back(pdr);
//         break;
//       case INTERFACE_VALUE_SGI_LAN_N6_LAN:
//       case INTERFACE_VALUE_CP_FUNCTION:
//       case INTERFACE_VALUE_LI_FUNCTION:
//         // TODO: if needed, handle these cases
//         break;
//       default:
//         // Handle default case if needed
//         break;
//     }
//   }

//   if ((pdrs_uplink.empty()) && (pdrs_downlink.empty())) {
//     logger.error("No PDR was found in session %d", seid);
//     throw std::runtime_error("No PDR was found in session");
//   }

//   std::sort(pdrs_uplink.begin(), pdrs_uplink.end(), comparePDR);
//   std::sort(pdrs_downlink.begin(), pdrs_downlink.end(), comparePDR);

//   auto pPFCP_Session_LookupProgram =
//       UserPlaneComponent::getInstance().getPFCP_Session_LookupProgram();

//   if (!pdrs_uplink.empty()) {
//     auto pdrHighPrecedenceUl = pdrs_uplink.front();
//     logger.debug(
//         "The Uplink PDR %d has the Highest Precedence",
//         pdrHighPrecedenceUl->pdr_id.rule_id);
//     createBPFSessionUL(pSession_establishment, pdrHighPrecedenceUl);
//   }

//   if (!pdrs_downlink.empty()) {
//     auto pdrHighPrecedenceDl = pdrs_downlink.front();
//     logger.debug(
//         "The Downlink PDR %d has the Highest Precedence",
//         pdrHighPrecedenceDl->pdr_id.rule_id);
//     createBPFSessionDL(pSession_establishment, pdrHighPrecedenceDl);
//   }

//   mSeidToSession[seid] = pSession_establishment;
// }

void SessionManager::createBPFSession(
    std::shared_ptr<pfcp::pfcp_session> pSession_establishment,
    itti_n4_session_establishment_request* est_req,
    itti_n4_session_modification_request* mod_req,
    itti_n4_session_deletion_request* del_req) {
  auto& logger  = Logger::upf_n4();
  uint64_t seid = pSession_establishment->get_up_seid();

  logger.debug("Session %d Received", seid);
  logger.debug("Preparing the Datapath ...");
  logger.debug("Find the PDR with Highest Precedence");

  auto& pdrs_uplink   = pSession_establishment->pdrs_uplink;
  auto& pdrs_downlink = pSession_establishment->pdrs_downlink;

  auto& qers_uplink   = pSession_establishment->qers_uplink;
  auto& qers_downlink = pSession_establishment->qers_downlink;

  // Process PDRs to populate uplink and downlink vectors
  processPDRs(pSession_establishment);

  // Throw error if both uplink and downlink vectors are empty
  if (pdrs_uplink.empty() && pdrs_downlink.empty()) {
    logger.error("No PDRs were found in session: %d", seid);
    throw std::runtime_error("No PDRs were found in session");
  }

  // Sort uplink and downlink vectors
  sortPDRs(pdrs_uplink, pdrs_downlink);

  // Create BPF sessions for uplink and downlink directions
  createSessionDirection(pSession_establishment, pdrs_uplink, "Uplink");
  createSessionDirection(pSession_establishment, pdrs_downlink, "Downlink");

  // Store the session in the session map
  mSeidToSession[seid] = pSession_establishment;
}

/*****************************************************************************************************************/
void SessionManager::processPDRs(
    std::shared_ptr<pfcp::pfcp_session> pSession_establishment) {
  auto& pdrs_uplink   = pSession_establishment->pdrs_uplink;
  auto& pdrs_downlink = pSession_establishment->pdrs_downlink;

  auto& qers_uplink   = pSession_establishment->qers_uplink;
  auto& qers_downlink = pSession_establishment->qers_downlink;

  // Iterate over PDRs and categorize them into uplink and downlink vectors
  for (auto& pdr : pSession_establishment->pdrs) {
    pfcp::pdi pdi;
    pfcp::source_interface_t sourceInterface;
    if (!(pdr->get(pdi) && pdi.get(sourceInterface))) {
      throw std::runtime_error(
          "Missing Mandatory IE (PDI or Source Interface) within PDR: " +
          std::to_string(pdr->pdr_id.rule_id));
    }

    uint64_t qer_id                     = pdr->qer_id.second.qer_id;
    std::shared_ptr<pfcp::pfcp_qer> qer = nullptr;

    for (auto& q : pSession_establishment->qers) {
      if (q->qer_id.second.qer_id == qer_id) {
        qer = q;
        break;
      }
    }

    if (!qer) {
      Logger::upf_n4().error(
          "QER not found for PDR: " + std::to_string(pdr->pdr_id.rule_id));
    }

    switch (sourceInterface.interface_value) {
      case INTERFACE_VALUE_ACCESS: {
        pdrs_uplink.push_back(pdr);
        if (qer) {
          qers_uplink.push_back(qer);
        }
        break;
      }
      case INTERFACE_VALUE_CORE: {
        pdrs_downlink.push_back(pdr);
        if (qer) {
          qers_downlink.push_back(qer);
        }
        break;
      }
      case INTERFACE_VALUE_SGI_LAN_N6_LAN:
      case INTERFACE_VALUE_CP_FUNCTION:
      case INTERFACE_VALUE_LI_FUNCTION:
        // TODO: if needed, handle these cases
        break;
      default:
        // Handle default case if needed
        break;
    }
  }
}

/*****************************************************************************************************************/
void SessionManager::sortPDRs(
    std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs_uplink,
    std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs_downlink) {
  // Sort uplink and downlink vectors
  std::sort(pdrs_uplink.begin(), pdrs_uplink.end(), comparePDR);
  std::sort(pdrs_downlink.begin(), pdrs_downlink.end(), comparePDR);
}

/*****************************************************************************************************************/
void SessionManager::createSessionDirection(
    std::shared_ptr<pfcp::pfcp_session> pSession_establishment,
    std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs,
    const std::string& direction) {
  auto& logger = Logger::upf_app();
  // Create BPF sessions for the specified direction
  if (!pdrs.empty()) {
    auto pdrHighPrecedence = pdrs.front();
    logger.debug(
        "The $s PDR %d has the Highest Precedence", direction,
        pdrHighPrecedence->pdr_id.rule_id);
    if (direction == "Uplink") {
      createBPFSessionUL(pSession_establishment, pdrHighPrecedence);
    } else {
      createBPFSessionDL(pSession_establishment, pdrHighPrecedence);
    }
  }
}

/*****************************************************************************************************************/
void SessionManager::createBPFSessionUL(
    std::shared_ptr<pfcp::pfcp_session> pSession,
    std::shared_ptr<pfcp::pfcp_pdr> pdrHighPrecedenceUl) {
  auto& logger = Logger::upf_app();

  // Common PDR processing
  processPDRDetails(
      pSession, pdrHighPrecedenceUl, INTERFACE_VALUE_ACCESS, "Uplink");
}

/*---------------------------------------------------------------------------------------------------------------*/
void SessionManager::createBPFSessionDL(
    std::shared_ptr<pfcp::pfcp_session> pSession,
    std::shared_ptr<pfcp::pfcp_pdr> pdrHighPrecedenceDl) {
  auto& logger = Logger::upf_app();

  // Common PDR processing
  processPDRDetails(
      pSession, pdrHighPrecedenceDl, INTERFACE_VALUE_CORE, "Downlink");
}

/*****************************************************************************************************************/
void SessionManager::processPDRDetails(
    std::shared_ptr<pfcp::pfcp_session> pSession,
    std::shared_ptr<pfcp::pfcp_pdr> pdrHighPrecedence, int interfaceValue,
    const std::string& direction) {
  auto& logger = Logger::upf_app();

  pfcp::pdi pdi;
  pfcp::fteid_t fteid;
  pfcp::ue_ip_address_t ueIpAddress;
  pfcp::source_interface_t sourceInterface;
  uint16_t pdr_id = pdrHighPrecedence->pdr_id.rule_id;

  logger.debug(
      "Create the %s Direction Datapath for Session %d", direction,
      pSession->get_up_seid());

  if (!(pdrHighPrecedence->get(pdi) && pdi.get(sourceInterface))) {
    throw std::runtime_error(
        "Missing Mandatory IE (PDI or Source Interface) within PDR: " +
        std::to_string(pdr_id));
  }

  if (!pdi.get(fteid)) {
    if (fteid.ch) {
    }
    fteid.teid = -1;
    logger.debug("FTEID is missing");
    logger.warn(
        "TODO: This IE shall not be present if Traffic Endpoint ID is present");
    logger.warn(
        "TODO: The CP function shall set the CHOOSE (CH) bit to 1 if the");
    logger.warn(
        "UP function supports the allocation of F-TEID and the CP function");
    logger.warn(
        "requests the UP function to assign a local F-TEID to the PDR.");
  }

  if (!pdi.get(ueIpAddress)) {
    ueIpAddress.ipv4_address.s_addr = 0;
    logger.debug("UE IP Address is missing");
    logger.warn(
        "TODO: This IE shall not be present if Traffic Endpoint ID is present");
  }

  logger.debug("PDI extracted from %s PDR %d", direction, pdr_id);
  logger.debug(
      "Extract %s FAR from the highest precedence %s PDR", direction,
      direction);

  std::shared_ptr<pfcp::pfcp_far> pFar;

  if (!extractFar(pdrHighPrecedence, pSession, pFar)) {
    throw std::runtime_error(
        "Failed to extract %s FAR for PDR " + direction + " " +
        std::to_string(pdr_id));
  }

  std::vector<std::shared_ptr<pfcp::pfcp_qer>> pQer;

  if (upf_cfg.enable_qos) {
    pQer = (direction == "Uplink") ? pSession->qers_uplink :
                                     pSession->qers_downlink;
  }

  SessionProgramManager::getInstance().createPipeline(
      pSession->get_up_seid(), fteid.teid, interfaceValue,
      ueIpAddress.ipv4_address.s_addr, pFar, pQer, false, 0);
}

/*---------------------------------------------------------------------------------------------------------------*/
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

/*---------------------------------------------------------------------------------------------------------------*/
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

/*---------------------------------------------------------------------------------------------------------------*/

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
    Logger::upf_app().error("Uplink TEID not found for session: 0x%x", seidul);
    SessionProgramManager::getInstance().createPipeline(
        seidul, fteid.teid, INTERFACE_VALUE_CORE,
        ueIpAddress.ipv4_address.s_addr, pFar, pSession->qers, true, 0);
  }
}

/*---------------------------------------------------------------------------------------------------------------*/
void SessionManager::removeBPFSession(
    std::shared_ptr<pfcp::pfcp_session> pSession,
    itti_n4_session_establishment_request* est_req,
    itti_n4_session_modification_request* mod_req,
    itti_n4_session_deletion_request* del_req) {
  uint64_t seid = pSession->get_up_seid();

  if (mSeidToSession.find(seid) == mSeidToSession.end()) {
    Logger::upf_app().error(
        "Session %d Does Not Exist. It Cannot be Removed", seid);
    // throw std::runtime_error("Session Does Not Exist. It Cannot be Removed");
  }

  SessionProgramManager::getInstance().removePipeline(seid);
  Logger::upf_app().debug("Session 0x%x Has Been Removed Successfully", seid);
}

/*---------------------------------------------------------------------------------------------------------------*/
bool SessionManager::comparePDR(
    const std::shared_ptr<pfcp::pfcp_pdr>& pFirst,
    const std::shared_ptr<pfcp::pfcp_pdr>& pSecond) {
  pfcp::precedence_t precedenceFirst, precedenceSecond;
  // TODO: Check if exists.
  pFirst->get(precedenceFirst);
  pSecond->get(precedenceSecond);
  return precedenceFirst.precedence < precedenceSecond.precedence;
}

/*---------------------------------------------------------------------------------------------------------------*/
void SessionManager::removeSession(uint64_t seid) {
  SessionProgramManager::getInstance().remove(seid);
  Logger::upf_app().debug("Session %d has been removed", seid);
}

/*---------------------------------------------------------------------------------------------------------------*/
