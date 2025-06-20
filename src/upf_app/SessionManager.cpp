#include "SessionManager.h"
#include <linux/if_ether.h>
#include <pfcp_session_pdr_lookup_xdp_user.h>
#include <SessionProgramManager.h>
#include <pfcp_session_lookup_xdp_user.h>
#include <bits/stdc++.h>  //sort
#include <interfaces/SessionBpf.h>
#include <pfcp/pfcp_session.h>
#include <wrappers/BPFMaps.h>
#include <next_prog_rule_key.h>
#include <mac_pdu_session_key.h>

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

// Helper function to extract ethernet pdu session information
bool SessionManager::extractEthernetPduSessionInformation(
    pfcp::pdi& pdi,
    pfcp::ethernet_pdu_session_information_t& ethernetPduSessionInformation) {
  return (pdi.get(ethernetPduSessionInformation));
}

// Helper function to extract ethernet packet filter
bool SessionManager::extractEthernetPacketFilter(
    pfcp::pdi& pdi, pfcp::ethernet_packet_filter& ethernetPacketFilter) {
  return (pdi.get(ethernetPacketFilter));
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
void SessionManager::createSession(std::shared_ptr<SessionBpf> pSession) {
  SessionProgramManager::getInstance().create(pSession->getSeid());
  Logger::upf_app().debug(
      "Session %d Has Been Created Successfully", pSession->getSeid());
}

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
void SessionManager::categorizePDRs(
    std::shared_ptr<pfcp::pfcp_session> session) {
  auto& logger = Logger::upf_n4();

  for (auto& pdr : session->pdrs) {
    pfcp::pdi pdi;
    pfcp::source_interface_t sourceInterface;

    if (!(pdr->get(pdi) && pdi.get(sourceInterface))) {
      throw std::runtime_error(
          "Missing Mandatory IE in PDR: " +
          std::to_string(pdr->pdr_id.rule_id));
    }

    std::shared_ptr<pfcp::pfcp_qer> qer;

    switch (sourceInterface.interface_value) {
      case INTERFACE_VALUE_ACCESS: {
        session->pdrs_uplink.push_back(pdr);
        if (getQer(session, pdr, qer)) {
          session->qers_uplink.push_back(qer);
        }
        break;
      }
      case INTERFACE_VALUE_CORE: {
        session->pdrs_downlink.push_back(pdr);
        if (getQer(session, pdr, qer)) {
          session->qers_downlink.push_back(qer);
        }
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
  std::sort(pdrs.begin(), pdrs.end(), comparePDR);
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
void SessionManager::processPDRDetails(
    std::shared_ptr<pfcp::pfcp_session> pSession,
    std::shared_ptr<pfcp::pfcp_pdr> pdrHighPrecedence, int interfaceValue,
    const std::string& direction) {
  auto& logger = Logger::upf_app();

  pfcp::pdi pdi;
  pfcp::fteid_t fteid;
  pfcp::ue_ip_address_t ueIpAddress;
  pfcp::ethernet_packet_filter ethernetPacketFilter;
  pfcp::ethernet_pdu_session_information_t ethernetPduSessionInformation;
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

  if (upf_cfg.enable_fr && direction == "Downlink") {
    if (ueIpAddress.v4) {
      std::vector<pfcp::framed_route_t> framedRoutes;
      if (pdi.get(framedRoutes)) {
        SessionProgramManager::getInstance().addFramedRoutes(
            ueIpAddress.ipv4_address.s_addr, framedRoutes);
      }
    } else {
      Logger::upf_app().warn("Framed Route is not yet supported for Ipv6");
    }
  }

  if (upf_cfg.enable_qos) {
    pQer = (direction == "Uplink") ? pSession->qers_uplink :
                                     pSession->qers_downlink;
  }

  // TODO [ETH-PDU] handle UE MAC address
  if (interfaceValue == INTERFACE_VALUE_ACCESS &&
      pdi.get(ethernetPacketFilter)) {  // UL only. For DL we will used the
                                        // learned MAC
    logger.debug("ETH-PDU: creating pipeline for ETH PDU session");
    pfcp::ethertype_t ethertype;
    if (!ethernetPacketFilter.get(ethertype)) {
      ethertype.ethertype = 0;
    }
    // TODO [ETH-PDU] support other packet filters
    logger.info(
        "ETH-PDU: Only considering Ethertype from the Ethernet Packet Filter "
        "IE");
    SessionProgramManager::getInstance().createPipeline(
        pSession->get_up_seid(), fteid.teid, interfaceValue,
        ethertype.ethertype, pFar, pQer, false, 0);
    return;
  }

  if (!pdi.get(ueIpAddress)) {
    ueIpAddress.ipv4_address.s_addr = 0;
    logger.debug("UE IP Address is missing");
    logger.warn(
        "TODO: This IE shall not be present if Traffic Endpoint ID is present");
  }

  logger.info("Running IP PDU session");

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
    uint32_t teid_ul = findUplinkTeid(
        seid, sessions);  // should be saved in ebpf_session at establishment
    if (teid_dl) {
      if (teid_ul) {
        SessionProgramManager::getInstance().modifyPipeline(
            session, teid_ul, teid_dl);
      } else {
        SessionProgramManager::getInstance().modifyPipeline(
            session, 0, teid_dl);
      }

      if (sourceInterface.interface_value == INTERFACE_VALUE_ACCESS) {
        pSession->pdrs_uplink.push_back(pSession->pdrs[i]);
      }
    }

    if ((pSession->pdrs_uplink.empty()) && (pSession->pdrs_downlink.empty())) {
      Logger::upf_app().error("No PDR was found in session %d", pSession->seid);
      return;
    }

    /** NOTE: Start with UL PDRs. ETH-PDU session uses a single map (eth_pdu)
     * for the for the PDRs with a key of UL TEID, and ethertype, and value of
     * DL TEID. DL requires a different map with a key of MAC address with the
     * DL TEID being fetch from eth_pdu during uplink. If we update the UL PDRs
     * after the DL PDRs we will overwrite the DL TEID with 0.
     */
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

    if (pdrs_downlink_size != pSession->pdrs_downlink.size()) {
      std::sort(
          pSession->pdrs_downlink.begin(), pSession->pdrs_downlink.end(),
          SessionManager::comparePDR);

      auto pdrHighPrecedenceDl = pSession->pdrs_downlink[0];
      Logger::upf_app().debug(
          "The Downlink PDR %u has the Highest Precedence",
          pdrHighPrecedenceDl->pdr_id.rule_id);

      Logger::upf_app().debug(
          "Extract PDI from the Downlink PDR %d",
          pdrHighPrecedenceDl->pdr_id.rule_id);

      updateBPFSessionDL(pSession, pdrHighPrecedenceDl);
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
      uint32_t teid_ul = findUplinkTeid(
          seid, sessions);  // should be saved in ebpf_session at establishment
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

/*---------------------------------------------------------------------------------------------------------------*/
void SessionManager::updateBPFSessionUL(
    std::shared_ptr<pfcp::pfcp_session> pSession,
    std::shared_ptr<pfcp::pfcp_pdr> pdrHighPrecedenceUl) {
  pfcp::pdi pdi;
  pfcp::fteid_t fteid;
  pfcp::ue_ip_address_t ueIpAddress;
  pfcp::source_interface_t sourceInterface;
  pfcp::ethernet_packet_filter ethernetPacketFilter;
  pfcp::ethernet_pdu_session_information_t ethernetPduSessionInformation;

  Logger::upf_app().debug(
      "Update the Uplink Direction Datapath For Session %d",
      pSession->get_up_seid());

  if (!(extractPdi(pdrHighPrecedenceUl, pdi) &&
        extractSourceIface(pdi, sourceInterface))) {
    Logger::upf_n4().error("No fields available For Uplink Update PDI Check");
    return;
  }

  std::shared_ptr<pfcp::pfcp_far> pFar;

  if (!extractFar(pdrHighPrecedenceUl, pSession, pFar)) {
    Logger::upf_n4().error("No fields available For Uplink Update FAR Check");
    return;
  }

  if (!pdi.get(fteid)) {
    if (fteid.ch) {
    }
    fteid.teid = -1;
    Logger::upf_app().warn("FTEID is missing");
    Logger::upf_app().warn(
        "TODO: This IE shall not be present if Traffic Endpoint ID is present");
    Logger::upf_app().warn(
        "TODO: The CP function shall set the CHOOSE (CH) bit to 1 if the");
    Logger::upf_app().warn(
        "UP function supports the allocation of F-TEID and the CP function");
    Logger::upf_app().warn(
        "requests the UP function to assign a local F-TEID to the PDR.");
  }

  // IP PDU session
  if (extractUeIpv4(pdi, ueIpAddress)) {
    Logger::upf_app().debug(
        "PDI extracted from Uplink PDR %d",
        pdrHighPrecedenceUl->pdr_id.rule_id);

    Logger::upf_app().debug(
        "Extract Uplink FAR from the highest precedence Uplink PDR");

    Logger::upf_app().info("Update Session For Uplink");
    Logger::upf_app().warn("TODO: update Uplink PDRs ...");
  } else if (
      extractEthernetPacketFilter(pdi, ethernetPacketFilter) ||
      extractEthernetPduSessionInformation(
          pdi, ethernetPduSessionInformation)) {
    pfcp::ethertype_t ethertype;
    if (!ethernetPacketFilter.get(ethertype)) {
      ethertype.ethertype = 0;
    }
    Logger::upf_app().info(
        "ETH-PDU: creating pipeline with ethertype: 0x%x", ethertype.ethertype);
    SessionProgramManager::getInstance().createPipeline(
        pSession->get_up_seid(), fteid.teid, INTERFACE_VALUE_ACCESS,
        ethertype.ethertype, pFar, pSession->qers, false, 0);
    return;

  } else {
    Logger::upf_n4().error("No fields available For Uplink Update PDI Check");
    return;
  }
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
  pfcp::ethernet_packet_filter ethernetPacketFilter;
  pfcp::ethernet_pdu_session_information_t ethernetPduSessionInformation;

  if (!(extractPdi(pdrHighPrecedenceDl, pdi) &&
        extractSourceIface(pdi, sourceInterface))) {
    Logger::upf_n4().error("No fields available For Downlink Update PDI Check");
    return;
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
    Logger::upf_n4().error("No fields available For Downlink Update FAR Check");
    return;
  }

  Logger::upf_app().debug("FAR ID %d", pFar->far_id.far_id);

  pfcp::forwarding_parameters forwardingParams;

  if (!extractForwardingParams(pFar, forwardingParams)) {
    Logger::upf_app().error(
        "Forwarding parameters were not found for Downlink Update");
  }

  // Get the teid_uplink for pSession
  uint64_t teid_ul           = 0;
  pfcp::fteid_t uplink_fteid = {};
  if (pSession->get(uplink_fteid)) {
    teid_ul = uplink_fteid.teid;
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
  fteid.teid = forwardingParams.outer_header_creation.second.teid;

  // IP PDU session
  if (extractUeIpv4(pdi, ueIpAddress)) {
    Logger::upf_app().debug(
        "IP PDU: PDI extracted from Downlink PDR %d",
        pdrHighPrecedenceDl->pdr_id.rule_id);

    if (upf_cfg.enable_fr) {
      if (ueIpAddress.v4) {
        std::vector<pfcp::framed_route_t> framedRoutes;
        if (pdi.get(framedRoutes)) {
          SessionProgramManager::getInstance().addFramedRoutes(
              ueIpAddress.ipv4_address.s_addr, framedRoutes);
        }
      } else {
        Logger::upf_app().warn("Framed Route is not yet supported for Ipv6");
      }
    }

    SessionProgramManager::getInstance().createPipeline(
        seidul, fteid.teid, INTERFACE_VALUE_CORE,
        ueIpAddress.ipv4_address.s_addr, pFar, pSession->qers, true, teid_ul);
    return;
  } else if (
      extractEthernetPacketFilter(pdi, ethernetPacketFilter) ||
      extractEthernetPduSessionInformation(
          pdi, ethernetPduSessionInformation)) {  // ETH-PDU session
    // TODO [ETH-PDU] handle UE MAC address
    // TODO [ETH-PDU] handle ethernetPduSessionInformation (currently default
    // set to 1)
    // TODO [ETH-PDU] handle ethernetPacketFilter
    Logger::upf_app().debug(
        "ETH-PDU: creating pipeline for ETH PDU session, Downlink PDR %d",
        pdrHighPrecedenceDl->pdr_id.rule_id);
    pfcp::ethertype_t ethertype;
    if (!ethernetPacketFilter.get(ethertype)) {
      ethertype.ethertype = 0;
    }
    Logger::upf_app().info(
        "ETH-PDU: creating pipeline with ethertype: 0x%x", ethertype.ethertype);
    SessionProgramManager::getInstance().createPipeline(
        pSession->get_up_seid(), teid_ul, INTERFACE_VALUE_CORE,
        ethertype.ethertype, pFar, pSession->qers, false, teid_ul);
    return;
  } else {
    Logger::upf_n4().error("No fields available For Downlink Update PDI Check");
    return;
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
