/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */
#include "SessionManager.h"
#include <SessionProgramManager.h>
#include <pfcp_session_lookup_xdp_user.h>
#include <bits/stdc++.h>  //sort
#include <interfaces/SessionBpf.h>
#include <pfcp/pfcp_session.h>
#include <wrappers/BPFMaps.h>
#include "logger.hpp"
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
uint64_t SessionManager::findUplinkTeid(
    const std::shared_ptr<pfcp::pfcp_session> session) {
  uint32_t ret = 0;  // Default TEID value

  std::shared_ptr<pfcp::pfcp_far> far;
  pfcp::forwarding_parameters forwardingParams;

  Logger::upf_app().debug(
      "Retrieving teid from session seid " SEID_FMT " ",
      session->get_up_seid());

  for (const auto& pdr : session->pdrs_uplink) {
    pfcp::pdi pdi;
    pfcp::source_interface_t sourceInterface;

    if (!(pdr->get(pdi) && pdi.get(sourceInterface))) {
      Logger::upf_app().error(
          "Missing Mandatory IE in pdr: %d", pdr->pdr_id.rule_id);
      throw std::runtime_error("Missing Mandatory ie in pdr");
    }

    if (pdr->outer_header_removal.first) {
      Logger::upf_app().debug(
          "Session seid " SEID_FMT " has outer header removal",
          session->get_up_seid());
      ret = pdi.local_fteid.second.teid;
      Logger::upf_app().debug(
          "Session seid " SEID_FMT " has teid " TEID_FMT " ",
          session->get_up_seid(), ret);
      break;
    }
  }

  return ret;
}

//---------------------------------------------------------------------------------------------------------------
void SessionManager::categorizePDRs(
    std::shared_ptr<pfcp::pfcp_session> session) {
  auto& logger = Logger::upf_n4();

  logger.debug(
      "Categorising %zu PDRs for SEID " SEID_FMT, session->pdrs.size(),
      session->get_up_seid());

  for (auto& pdr : session->pdrs) {
    pfcp::pdi pdi;
    pfcp::source_interface_t sourceInterface;
    pfcp::precedence_t precedence;

    if (!(pdr->get(pdi) && pdi.get(sourceInterface))) {
      throw std::runtime_error(
          "Missing Mandatory IE in PDR: " +
          std::to_string(pdr->pdr_id.rule_id));
    }

    std::shared_ptr<pfcp::pfcp_qer> qer;
    uint8_t qfi = 0;
    if (pdr->get(precedence) && getQer(session, pdr, qer) && qer->qfi.first) {
      qfi = qer->qfi.second.qfi;
    }

    switch (sourceInterface.interface_value) {
      case INTERFACE_VALUE_ACCESS: {
        session->pdrs_uplink.push_back(pdr);
        if (getQer(session, pdr, qer)) {
          session->qers_uplink.push_back(qer);
        }
        logger.debug(
            "  PDR %u -> UPLINK (Precedence: %u, QFI: %u)", pdr->pdr_id.rule_id,
            pdr->get(precedence) ? precedence.precedence : 0, qfi);
        break;
      }
      case INTERFACE_VALUE_CORE: {
        session->pdrs_downlink.push_back(pdr);
        if (getQer(session, pdr, qer)) {
          session->qers_downlink.push_back(qer);
        }
        logger.debug(
            "  PDR %u -> DOWNLINK (Precedence: %u, QFI: %u)",
            pdr->pdr_id.rule_id,
            pdr->get(precedence) ? precedence.precedence : 0, qfi);
        break;
      }
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
}

//---------------------------------------------------------------------------------------------------------------
std::shared_ptr<pfcp::pfcp_qer> SessionManager::findQER(
    std::shared_ptr<pfcp::pfcp_session> session, uint32_t qer_id) {
  for (auto& qer : session->qers) {
    if (qer->qer_id.second.qer_id == qer_id) {
      return qer;
    }
  }
  return nullptr;
}

//---------------------------------------------------------------------------------------------------------------
bool SessionManager::getQer(
    std::shared_ptr<pfcp::pfcp_session> session,
    std::shared_ptr<pfcp::pfcp_pdr> pdr,
    std::shared_ptr<pfcp::pfcp_qer>& outQer) {
  pfcp::qer_id_t qerId;

  return (pdr->get(qerId) && session->get(qerId.qer_id, outQer));
}

//---------------------------------------------------------------------------------------------------------------
void SessionManager::sortPDRs(
    std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs) {
  auto& logger = Logger::upf_n4();

  // Log PDR order before sorting
  logger.debug("PDRs before sorting by precedence:");
  for (size_t i = 0; i < pdrs.size(); i++) {
    pfcp::precedence_t prec;
    if (pdrs[i]->get(prec)) {
      logger.debug(
          "  [%zu] PDR %u (Precedence: %u)", i, pdrs[i]->pdr_id.rule_id,
          prec.precedence);
    }
  }

  std::sort(pdrs.begin(), pdrs.end(), comparePDR);

  // Log PDR order after sorting
  logger.debug(
      "PDRs after sorting by precedence (lower value = higher priority):");
  for (size_t i = 0; i < pdrs.size(); i++) {
    pfcp::precedence_t prec;
    if (pdrs[i]->get(prec)) {
      logger.debug(
          "  [%zu] PDR %u (Precedence: %u)", i, pdrs[i]->pdr_id.rule_id,
          prec.precedence);
    }
  }
}

//---------------------------------------------------------------------------------------------------------------
bool SessionManager::getFar(
    std::shared_ptr<pfcp::pfcp_session> session,
    std::shared_ptr<pfcp::pfcp_pdr> pdr,
    std::shared_ptr<pfcp::pfcp_far>& outFar) {
  pfcp::far_id_t farId;

  return (pdr->get(farId) && session->get(farId.far_id, outFar));
}

//---------------------------------------------------------------------------------------------------------------
uint32_t SessionManager::retrieveTeid(
    std::shared_ptr<pfcp::pfcp_session> session) {
  uint32_t ret = 0;  // Default TEID value

  std::shared_ptr<pfcp::pfcp_far> far;
  pfcp::forwarding_parameters forwardingParams;

  Logger::upf_app().debug(
      "Retrieving teid from session seid " SEID_FMT " ",
      session->get_up_seid());

  for (const auto& pdr : session->pdrs_downlink) {
    pfcp::pdi pdi;
    pfcp::source_interface_t sourceInterface;

    if (!(pdr->get(pdi) && pdi.get(sourceInterface))) {
      Logger::upf_app().error(
          "Missing Mandatory IE in pdr: %d", pdr->pdr_id.rule_id);
      throw std::runtime_error("Missing Mandatory ie in pdr");
    }

    if (!getFar(session, pdr, far)) {
      Logger::upf_app().error(
          "Failed to retrieve far for pdr: %d", pdr->pdr_id.rule_id);
      throw std::runtime_error("Failed to retrieve far for pdr");
    }

    if (far->get(forwardingParams) &&
        forwardingParams.outer_header_creation.first) {
      ret = forwardingParams.outer_header_creation.second.teid;
      Logger::upf_app().debug(
          "Session seid " SEID_FMT " has teid " TEID_FMT " ",
          session->get_up_seid(), ret);
      break;
    }
  }

  return ret;
}

//---------------------------------------------------------------------------------------------------------------
void SessionManager::createBpfSession(
    std::shared_ptr<pfcp::pfcp_session> session,
    itti_n4_session_establishment_request* est_req,
    itti_n4_session_modification_request* mod_req,
    itti_n4_session_deletion_request* del_req) {
  auto& logger  = Logger::upf_app();
  uint64_t seid = session->get_up_seid();
  sessions.push_back(session);
  logger.debug("sessionManager::createBpfSession() seid " SEID_FMT " ", seid);

  categorizePDRs(session);
  if (session->pdrs_uplink.empty() && session->pdrs_downlink.empty()) {
    logger.error("No pdr found in session seid " SEID_FMT " ", seid);
    throw std::runtime_error("Session creation failed: No pdr found.");
  }

  sortPDRs(session->pdrs_uplink);
  sortPDRs(session->pdrs_downlink);

  // for (auto direction : {Direction::Uplink, Direction::Downlink}) {
  //   auto& pdrs = (direction == Direction::Uplink) ? session->pdrs_uplink :
  //                                                   session->pdrs_downlink;
  //   if (pdrs.empty()) {
  //     logger.warn(
  //         "NO PDR available for %s direction",
  //         (direction == Direction::Uplink) ? "Uplink" : "Downlink");
  //     continue;
  //   }

  //   auto pdr = pdrs.front();
  //   pfcp::pdi pdi;
  //   pfcp::fteid_t fteid;
  //   pfcp::ue_ip_address_t ueIpAddress;
  //   pfcp::source_interface_t sourceInterface;
  //   uint16_t pdr_id = pdr->pdr_id.rule_id;

  //   if (!(pdr->get(pdi) && pdi.get(sourceInterface))) {
  //     throw std::runtime_error(
  //         "Missing Mandatory IE in PDR: " + std::to_string(pdr_id));
  //   }

  //   if (!pdi.get(fteid)) {
  //     fteid.teid = -1;
  //     logger.warn(
  //         "FTEID is missing for PDR %d. CH bit: %s", pdr_id,
  //         fteid.ch ? "Set" : "Not Set");
  //   }

  //   if (!pdi.get(ueIpAddress)) {
  //     ueIpAddress.ipv4_address.s_addr = 0;
  //     logger.warn("UE IP Address is missing for PDR %d", pdr_id);
  //   }

  //   logger.debug("Processing PDR %d", pdr_id);
  //   std::shared_ptr<pfcp::pfcp_far> pFar;
  //   if (!getFar(session, pdr, pFar)) {
  //     throw std::runtime_error(
  //         "Error retrieving FAR for PDR ID: " + std::to_string(pdr_id));
  //   }

  //   std::vector<std::shared_ptr<pfcp::pfcp_qer>> qers =
  //       (direction == Direction::Downlink) ?
  //           session->qers_downlink :
  //           std::vector<std::shared_ptr<pfcp::pfcp_qer>>{};

  SessionProgramManager::getInstance().createPipeline(session);

  // SessionProgramManager::getInstance().createPipeline(
  //     seid, fteid.teid, sourceInterface.interface_value,
  //     ueIpAddress.ipv4_address.s_addr, pFar, qers, pdrs, false, 0);

  // setupEbpfPipeline(session, session->pdrs_uplink, Direction::Uplink);
  // setupEbpfPipeline(session, session->pdrs_downlink, Direction::Downlink);

  mSeidToSession[seid] = session;

  logger.debug("Session seid " SEID_FMT " successfully created", seid);
}

//---------------------------------------------------------------------------------------------------------------
void SessionManager::modifyBpfSession(
    std::shared_ptr<pfcp::pfcp_session> session,
    itti_n4_session_establishment_request* est_req,
    itti_n4_session_modification_request* mod_req,
    itti_n4_session_deletion_request* del_req) {
  auto& logger  = Logger::upf_app();
  uint64_t seid = session->get_up_seid();

  logger.debug("sessionManager::modifyBpfSession() seid " SEID_FMT " ", seid);

  // Handle creation of PDRs
  if (!mod_req->pfcp_ies.create_pdrs.empty()) {
    logger.debug("modifyBpfSession:: add(pdr)");
    pfcp::fteid_t allocated_fteid = {};
    pfcp::far_id_t far_id         = {};

    categorizePDRs(session);

    if (session->pdrs_uplink.empty() && session->pdrs_downlink.empty()) {
      logger.error("No pdr found in session seid " SEID_FMT " ", seid);
      throw std::runtime_error("Session modification failed: No pdr found.");
    }

    sortPDRs(session->pdrs_uplink);
    sortPDRs(session->pdrs_downlink);

    pfcp::pdi pdi;
    pfcp::fteid_t fteid;
    pfcp::ue_ip_address_t ueIpAddress;
    pfcp::source_interface_t sourceInterface;

    uint32_t teid_dl = retrieveTeid(session);
    uint32_t teid_ul = findUplinkTeid(session);
    // uint32_t teid_ul = findUplinkTeid(
    //     seid, sessions);  // should be saved in ebpf_session at establishment
    if (teid_dl) {
      if (teid_ul) {
        SessionProgramManager::getInstance().modifyPipeline(
            session, teid_ul, teid_dl);
      } else {
        SessionProgramManager::getInstance().modifyPipeline(
            session, 0, teid_dl);
      }
    } else {
      Logger::upf_app().warn(
          "No valid teid found for session seid " SEID_FMT " ", seid);
      // Ethernet PDU Session
    }
  }

  if (!mod_req->pfcp_ies.create_fars.empty()) {
    logger.debug("modifyBpfSession:: add(far)");
    for (const auto& it : mod_req->pfcp_ies.create_fars) {
      /*
       * TODO: What should be done for FARs?
       *    1. Update Maching rules map
       *    2. Anything else ?
       */
    }
  }

  if (!mod_req->pfcp_ies.create_qers.empty()) {
    logger.debug("modifyBpfSession:: add(qer)");
    for (const auto& it : mod_req->pfcp_ies.create_qers) {
      /*
       * TODO: What should be done for QERs?
       *    1. Update Maching rules map
       *    2. Anything else ?
       */
    }
  }

  if (!mod_req->pfcp_ies.update_pdrs.empty()) {
    logger.debug("modifyBpfSession:: update(pdr)");
    for (const auto& it : mod_req->pfcp_ies.update_pdrs) {
      /*
       * TODO: What should be done for pdrs?
       *    1. Update Maching rules map
       *    2. Anything else ?
       */
    }
  }

  if (!mod_req->pfcp_ies.update_fars.empty()) {
    logger.debug("modifyBpfSession:: update(far)");
    for (const auto& it : mod_req->pfcp_ies.update_fars) {
      /*
       * TODO: What should be done for QERs?
       *    1. Update Maching rules map
       *    2. Anything else ?
       */
      pfcp::fteid_t allocated_fteid = {};
      pfcp::far_id_t far_id         = {};

      categorizePDRs(session);

      if (session->pdrs_uplink.empty() && session->pdrs_downlink.empty()) {
        logger.error("No pdr found in session seid " SEID_FMT " ", seid);
        throw std::runtime_error("Session modification failed: No pdr found.");
      }

      sortPDRs(session->pdrs_uplink);
      sortPDRs(session->pdrs_downlink);

      pfcp::pdi pdi;
      pfcp::fteid_t fteid;
      pfcp::ue_ip_address_t ueIpAddress;
      pfcp::source_interface_t sourceInterface;

      uint32_t teid_dl = retrieveTeid(session);
      uint32_t teid_ul = findUplinkTeid(session);
      // uint32_t teid_ul = findUplinkTeid(
      //     seid, sessions);  // should be saved in ebpf_session at
      //     establishment
      if (teid_dl) {
        if (teid_ul) {
          SessionProgramManager::getInstance().modifyPipeline(
              session, teid_ul, teid_dl);
        } else {
          SessionProgramManager::getInstance().modifyPipeline(
              session, 0, teid_dl);
        }
      } else {
        Logger::upf_app().warn(
            "No valid teid found for session seid " SEID_FMT " ", seid);
        // Ethernet PDU Session
      }
    }
  }

  if (!mod_req->pfcp_ies.update_qers.empty()) {
    logger.debug("modifyBpfSession:: update(qer)");
    for (const auto& it : mod_req->pfcp_ies.update_qers) {
      /*
       * TODO: What should be done for QERs?
       *    1. Update Maching rules map
       *    2. Anything else ?
       */
    }
  }

  // Handle PDR removal requests (for modification or deletion)
  for (auto it : mod_req->pfcp_ies.remove_pdrs) {
    Logger::upf_app().debug("Delete pdr");
    Logger::upf_app().debug(
        "pdr and far map entries are obsolete and need to be deleted");

    pfcp::pdr_id_t pdr_id;
    if (it.get(pdr_id)) {
      Logger::upf_app().debug("Remove PDR with id %u", pdr_id.rule_id);
      for (auto pdr : session->pdrs) {
        if (pdr_id.rule_id == pdr->pdr_id.rule_id) {
          Logger::upf_app().debug(
              "Found PDR with id %u in list 'pdrs'", pdr_id.rule_id);
          // TODO:
          /*
          *
          * remove pdrs from session->pdrs; session->uplink_pdrs;
         session->downlink_pdrs;
         * sort pdrs, uplink_pdrs; downlink_pdrs
         * update maps: getRulesMatchPdrMap, getSessionPdrsMap
         * remove fars from session->fars; session->uplink_fars;
         session->downlink_fars;
         * remove qers from session->qers; session->uplink_qers;
         session->downlink_qers;
          */
          if (upf_cfg.enable_fr) {
            pfcp::pdi pdi;
            if (pdr->get(pdi)) {
              std::vector<pfcp::framed_route_t> framedRoutes;
              if (pdi.get(framedRoutes)) {
                SessionProgramManager::getInstance().removeFramedRoutes(
                    framedRoutes);
              }
            }
          }
        }
      }
    }
  }

  if (!mod_req->pfcp_ies.remove_fars.empty()) {
    logger.debug("modifBpfSession:: remove(far)");
    for (const auto& it : mod_req->pfcp_ies.remove_fars) {
      /*
       * TODO: What should be done for QERs?
       *    1. Update Maching rules map
       *    2. Anything else ?
       */
    }
  }

  if (!mod_req->pfcp_ies.remove_qers.empty()) {
    logger.debug("modifBpfSession:: remove(qer)");
    for (const auto& it : mod_req->pfcp_ies.remove_qers) {
      /*
       * TODO: What should be done for QERs?
       *    1. Update Maching rules map
       *    2. Anything else ?
       */
    }
  }
}

//---------------------------------------------------------------------------------------------------------------
void SessionManager::removeBpfSession(
    std::shared_ptr<pfcp::pfcp_session> pSession,
    itti_n4_session_establishment_request* est_req,
    itti_n4_session_modification_request* mod_req,
    itti_n4_session_deletion_request* del_req) {
  uint64_t seid = pSession->get_up_seid();
  Logger::upf_app().info("Session %lu will be deleted from Data-Path", seid);

  if (mSeidToSession.find(seid) == mSeidToSession.end()) {
    Logger::upf_app().error(
        "Session %d Does Not Exist. It Cannot be Removed", seid);
    // throw std::runtime_error("Session Does Not Exist. It Cannot be
    // Removed");
  }

  if (upf_cfg.enable_fr) {
    // Remove framed route to ue_ip mapping
    for (auto pdr : pSession->pdrs) {
      pfcp::pdi pdi;
      if (pdr->get(pdi)) {
        std::vector<pfcp::framed_route_t> framedRoutes;
        if (pdi.get(framedRoutes)) {
          SessionProgramManager::getInstance().removeFramedRoutes(framedRoutes);
        }
      }
    }
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
