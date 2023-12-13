#include "SessionManager.h"
#include <pfcp_session_pdr_lookup_ebpf_xdp_prgrm_user.h>
#include <SessionProgramManager.h>
#include <pfcp_session_lookup_ebpf_xdp_prgrm_user.h>
#include <bits/stdc++.h>  //sort
#include <interfaces/ForwardingActionRules.h>
#include <interfaces/PacketDetectionRules.h>
#include <interfaces/SessionBpf.h>
#include <pfcp/pfcp_session.h>
#include <wrappers/BPFMaps.h>
#include "logger.hpp"

#include <next_prog_rule_key.h>

#include "upf_config.hpp"

using namespace oai::config;
extern upf_config upf_cfg;

/*****************************************************************************************************************/
SessionManager::SessionManager() {}

/*****************************************************************************************************************/
SessionManager::~SessionManager() {}

/*****************************************************************************************************************/
// Helper function to extract PDI and source interface
bool SessionManager::extractPdiAndInterface(
    std::shared_ptr<pfcp::pfcp_pdr> pdr, pfcp::pdi& pdi,
    pfcp::source_interface_t& sourceInterface,
    pfcp::ue_ip_address_t& ueIpAddress) {
  return (pdr->get(pdi) && pdi.get(sourceInterface) && pdi.get(ueIpAddress));
}

/*****************************************************************************************************************/
// Helper function to extract FAR
bool SessionManager::extractFar(
    std::shared_ptr<pfcp::pfcp_pdr> pdr,
    std::shared_ptr<pfcp::pfcp_session> session,
    std::shared_ptr<pfcp::pfcp_far>& outFar) {
  pfcp::far_id_t farId;
  if (pdr->get(farId) && session->get(farId.far_id, outFar)) {
    return true;
  }
  return false;
}

/*****************************************************************************************************************/
// Helper function to extract Forwarding Parameters
bool SessionManager::extractForwardingParameters(
    std::shared_ptr<pfcp::pfcp_far> far,
    pfcp::forwarding_parameters& forwardingParams) {
  return far->get(forwardingParams);
}

/*****************************************************************************************************************/
// Helper function to find the Uplink TEID to update
uint32_t SessionManager::findUplinkTeid(
    uint32_t seid,
    const std::vector<std::shared_ptr<pfcp::pfcp_session>>& sessions) {
  uint32_t teidToUpdate = 0;

  for (const auto& session : sessions) {
    pfcp::pdi pdi;
    pfcp::source_interface_t sourceInterface;

    if (session->get_up_seid() == seid) {
      for (const auto& pdr : session->pdrs) {
        if (pdr->get(pdi)) {
          pdi.get(sourceInterface);
          if (sourceInterface.interface_value == INTERFACE_VALUE_ACCESS) {
            teidToUpdate = session->teid_uplink.teid;
            break;
          }
        }
      }
    }

    if (teidToUpdate != 0) {
      break;
    }
  }

  return teidToUpdate;
}

/*****************************************************************************************************************/
void SessionManager::createSession(std::shared_ptr<SessionBpf> pSession) {
  SessionProgramManager::getInstance().create(pSession->getSeid());
  Logger::upf_app().debug(
      "Session %d Has Been Cretead Successfully", pSession->getSeid());
}

/*****************************************************************************************************************/
void SessionManager::createBPFSession(
    std::shared_ptr<pfcp::pfcp_session> pSession_establishment,
    itti_n4_session_establishment_request* est_req,
    itti_n4_session_modification_request* mod_req,
    itti_n4_session_deletion_request* del_req) {
  Logger::upf_app().debug(
      "Session %d Received", pSession_establishment->get_up_seid());
  Logger::upf_app().debug("Preparing the Datapath ...");
  Logger::upf_app().debug("Find the PDR with Highest Precedence:");

  for (int i = 0; i < pSession_establishment->pdrs.size(); i++) {
    pfcp::pdi pdi;
    pfcp::source_interface_t sourceInterface;

    pSession_establishment->pdrs[i]->get(pdi);
    pdi.get(sourceInterface);

    if (sourceInterface.interface_value == INTERFACE_VALUE_ACCESS) {
      pSession_establishment->pdrs_uplink.push_back(
          pSession_establishment->pdrs[i]);
    }

    if (sourceInterface.interface_value == INTERFACE_VALUE_CORE) {
      pSession_establishment->pdrs_downlink.push_back(
          pSession_establishment->pdrs[i]);
    }
  }

  std::sort(
      pSession_establishment->pdrs_uplink.begin(),
      pSession_establishment->pdrs_uplink.end(), SessionManager::comparePDR);

  std::sort(
      pSession_establishment->pdrs_downlink.begin(),
      pSession_establishment->pdrs_downlink.end(), SessionManager::comparePDR);

  auto pPFCP_Session_LookupProgram =
      UserPlaneComponent::getInstance().getPFCP_Session_LookupProgram();

  if ((pSession_establishment->pdrs_uplink.empty()) &&
      (pSession_establishment->pdrs_downlink.empty())) {
    Logger::upf_app().error(
        "No PDR was found in session %d", pSession_establishment->seid);
    throw std::runtime_error("No PDR was found in session");
  }

  if (not(pSession_establishment->pdrs_uplink.empty())) {
    auto pdrHighPrecedenceUl = pSession_establishment->pdrs_uplink[0];

    Logger::upf_app().debug(
        "The Uplink PDR %d has the Highest Precedence",
        pdrHighPrecedenceUl->pdr_id.rule_id);

    Logger::upf_app().debug(
        "Extract PDI from the Uplink PDR %d",
        pdrHighPrecedenceUl->pdr_id.rule_id);

    pfcp::pdi pdi;
    pdrHighPrecedenceUl->get(pdi);
    pdi.get(pSession_establishment->teid_uplink);

    Logger::upf_app().info(
        "TEID for Uplink Session: %d",
        pSession_establishment->teid_uplink.teid);

    createBPFSessionUL(pSession_establishment, pdrHighPrecedenceUl);
  }

  if (not(pSession_establishment->pdrs_downlink.empty())) {
    auto pdrHighPrecedenceDl = pSession_establishment->pdrs_downlink[0];
    Logger::upf_app().debug(
        "The Downlink PDR %d has the Highest Precedence",
        pdrHighPrecedenceDl->pdr_id.rule_id);

    Logger::upf_app().debug(
        "Extract PDI from the Downlink PDR %d",
        pdrHighPrecedenceDl->pdr_id.rule_id);

    createBPFSessionDL(pSession_establishment, pdrHighPrecedenceDl);
  }

  mSeidToSession[pSession_establishment->get_up_seid()] =
      pSession_establishment;
}
/*****************************************************************************************************************/
void SessionManager::createBPFSessionUL(
    std::shared_ptr<pfcp::pfcp_session> pSession,
    std::shared_ptr<pfcp::pfcp_pdr> pdrHighPrecedenceUl) {
  pfcp::pdi pdi;
  pfcp::fteid_t fteid;
  pfcp::ue_ip_address_t ueIpAddress;
  pfcp::source_interface_t sourceInterface;
  pfcp::qfi_t qfi;

  Logger::upf_app().debug(
      "Create the Uplink Direction Datapath for Session %d",
      pSession->get_up_seid());

  if (!(pdrHighPrecedenceUl->get(pdi) && pdi.get(fteid) &&
        pdi.get(sourceInterface) && pdi.get(ueIpAddress))) {
    throw std::runtime_error("No fields available For Uplink Create PDI Check");
  }

  Logger::upf_app().debug(
      "PDI extracted from Uplink PDR %d", pdrHighPrecedenceUl->pdr_id.rule_id);

  Logger::upf_app().debug(
      "Extract Uplink FAR from the highest precedence Uplink PDR");
  std::shared_ptr<pfcp::pfcp_far> pFar;

  if (!extractFar(pdrHighPrecedenceUl, pSession, pFar)) {
    throw std::runtime_error("No fields available For Uplink Create FAR Check");
  }

  SessionProgramManager::getInstance().createPipeline(
      pSession->get_up_seid(), fteid.teid, INTERFACE_VALUE_ACCESS,
      ueIpAddress.ipv4_address.s_addr, pFar, false, 0);
}

/*****************************************************************************************************************/
void SessionManager::createBPFSessionDL(
    std::shared_ptr<pfcp::pfcp_session> pSession,
    std::shared_ptr<pfcp::pfcp_pdr> pdrHighPrecedenceDl) {
  pfcp::pdi pdi;
  pfcp::fteid_t fteid;
  pfcp::ue_ip_address_t ueIpAddress;
  pfcp::source_interface_t sourceInterface;

  Logger::upf_app().debug(
      "Create the Downlink Direction Datapath for Session %d",
      pSession->get_up_seid());

  if (!(pdrHighPrecedenceDl->get(pdi) && pdi.get(fteid) &&
        pdi.get(sourceInterface) && pdi.get(ueIpAddress))) {
    throw std::runtime_error(
        "No fields available for Downlink Create PDI Check");
  }

  Logger::upf_app().debug(
      "PDI extracted from Uplink PDR %d", pdrHighPrecedenceDl->pdr_id.rule_id);

  Logger::upf_app().debug(
      "Extract Downlink FAR from the highest precedence Downlink PDR");
  std::shared_ptr<pfcp::pfcp_far> pFar;

  if (!extractFar(pdrHighPrecedenceDl, pSession, pFar)) {
    throw std::runtime_error(
        "No fields available For Downlink Create FAR Check");
  }

  SessionProgramManager::getInstance().createPipeline(
      pSession->get_up_seid(), fteid.teid, INTERFACE_VALUE_CORE,
      ueIpAddress.ipv4_address.s_addr, pFar, false, 0);
}

/*****************************************************************************************************************/
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

/*****************************************************************************************************************/
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

  if (!extractPdiAndInterface(
          pdrHighPrecedenceUl, pdi, sourceInterface, ueIpAddress)) {
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

/*****************************************************************************************************************/

// Function to update the Downlink Direction of a session
void SessionManager::updateBPFSessionDL(
    std::shared_ptr<pfcp::pfcp_session> pSession,
    std::shared_ptr<pfcp::pfcp_pdr> pdrHighPrecedenceDl) {
  uint32_t seidul = pSession->get_up_seid();
  pfcp::pdi pdi;
  pfcp::fteid_t fteid;
  pfcp::ue_ip_address_t ueIpAddress;
  pfcp::source_interface_t sourceInterface;

  if (!extractPdiAndInterface(
          pdrHighPrecedenceDl, pdi, sourceInterface, ueIpAddress)) {
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

  if (!extractForwardingParameters(pFar, forwardingParams)) {
    Logger::upf_app().error(
        "Forwarding parameters were not found for Downlink Update");
  }

  fteid.teid       = forwardingParams.outer_header_creation.second.teid;
  uint32_t teid_ul = findUplinkTeid(seidul, sessions);

  if (teid_ul) {
    SessionProgramManager::getInstance().createPipeline(
        seidul, fteid.teid, INTERFACE_VALUE_CORE,
        ueIpAddress.ipv4_address.s_addr, pFar, true, teid_ul);
  } else {
    Logger::upf_app().error("Uplink TEID not found for session: 0x%x", seidul);
    SessionProgramManager::getInstance().createPipeline(
        seidul, fteid.teid, INTERFACE_VALUE_CORE,
        ueIpAddress.ipv4_address.s_addr, pFar, true, 0);
  }
}

/*****************************************************************************************************************/
void SessionManager::removeBPFSession(
    std::shared_ptr<pfcp::pfcp_session> pSession,
    itti_n4_session_establishment_request* est_req,
    itti_n4_session_modification_request* mod_req,
    itti_n4_session_deletion_request* del_req) {
  uint64_t seid = pSession->get_up_seid();

  if (mSeidToSession.find(seid) == mSeidToSession.end()) {
    Logger::upf_app().error(
        "Session %d Does Not Exist. It Cannot be Removed", seid);
    throw std::runtime_error("Session Does Not Exist. It Cannot be Removed");
  }

  SessionProgramManager::getInstance().removePipeline(seid);
  Logger::upf_app().debug("Session 0x%x Has Been Removed Successfully", seid);
}

/*****************************************************************************************************************/
bool SessionManager::comparePDR(
    const std::shared_ptr<pfcp::pfcp_pdr>& pFirst,
    const std::shared_ptr<pfcp::pfcp_pdr>& pSecond) {
  pfcp::precedence_t precedenceFirst, precedenceSecond;
  // TODO: Check if exists.
  pFirst->get(precedenceFirst);
  pSecond->get(precedenceSecond);
  return precedenceFirst.precedence < precedenceSecond.precedence;
}

/*****************************************************************************************************************/
void SessionManager::removeSession(uint64_t seid) {
  SessionProgramManager::getInstance().remove(seid);
  Logger::upf_app().debug("Session %d has been removed", seid);
}

/*****************************************************************************************************************/
