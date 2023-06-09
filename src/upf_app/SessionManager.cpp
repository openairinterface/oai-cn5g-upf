#include "SessionManager.h"
#include <pfcp_session_lookup_ebpf_xdp_prgrm_user.h>
#include <SessionProgramManager.h>
#include <pfcp_session_pdr_lookup_ebpf_xdp_prgrm_user.h>
#include <bits/stdc++.h>  //sort
#include <interfaces/ForwardingActionRules.h>
#include <interfaces/PacketDetectionRules.h>
#include <interfaces/SessionBpf.h>
#include <pfcp/pfcp_session.h>
// // #include <utils/LogDefines.h>
#include <wrappers/BPFMaps.h>
#include "logger.hpp"

#include <next_prog_rule_key.h>
// #include "common_defs.h"
// #include "logger.hpp"
// #include "msg_pfcp.hpp"
// #include "pfcp_session.hpp"
// #include "thread_sched.hpp"
// #include "uint_generator.hpp"

/*****************************************************************************************************************/
SessionManager::SessionManager() {
}

/*****************************************************************************************************************/
SessionManager::~SessionManager() { 
}

/*****************************************************************************************************************/
void SessionManager::createSession(std::shared_ptr<SessionBpf> pSession)
{
  SessionProgramManager::getInstance().create(pSession->getSeid());
  Logger::upf_app().debug("Session %d Has Been Cretead Successfully", pSession->getSeid());
}

/*****************************************************************************************************************/
void SessionManager::createBPFSession(std::shared_ptr<pfcp::pfcp_session> pSession)
{
  Logger::upf_app().debug("Session %d Received", pSession->get_up_seid());
  Logger::upf_app().debug("Preparing the Datapath ...");
  Logger::upf_app().debug("Find the PDR with Highest Precedence:");
  
  // The lower precedence values indicate higher precedence of the PDR, and the
  // higher precedence values indicate lower precedence of the PDR when matching
  // a packet.

  // TODO: Create a list for DL and UL. There will be two
  // deployment on the dataplane. One related to UL and other related to DL.
  // Today, we only deploy the highest priority. We dont take into account if it
  // is a DL or UP.
  std::sort(
      pSession->pdrs.begin(), pSession->pdrs.end(), SessionManager::comparePDR);

  Logger::upf_app().debug("Extract the key (PDI) from the highest priority PDR");
  auto pPFCP_Session_PDR_LookupProgram = UserPlaneComponent::getInstance().getPFCP_Session_PDR_LookupProgram();

  pfcp::pdi pdi;
  pfcp::fteid_t fteid;
  pfcp::ue_ip_address_t ueIpAddress;
  pfcp::source_interface_t sourceInterface;

  if (pSession->pdrs.empty()) {
    Logger::upf_app().error("No PDR was found in session %d", pSession->seid);
    throw std::runtime_error("No PDR was found in session");
  }

  auto pdrHighPriority = pSession->pdrs[0];
  if (!(pdrHighPriority->get(pdi) && pdi.get(fteid) &&
        pdi.get(sourceInterface) && pdi.get(ueIpAddress))) {
    throw std::runtime_error("No fields available");
  }
  
  Logger::upf_app().debug(
      "PDI extracted from PDR %d", pdrHighPriority->pdr_id.rule_id);

  // pPFCP_Session_PDR_LookupProgram->getNextProgRuleMap()->update(&next_rule_prog_index_key)
  Logger::upf_app().debug("Extract FAR from the highest priority PDR");
  std::shared_ptr<pfcp::pfcp_far> pFar;
  pfcp::far_id_t farId;

  if (!(pdrHighPriority->get(farId) && pSession->get(farId.far_id, pFar))) {
    throw std::runtime_error("No fields available");
  }

  SessionProgramManager::getInstance().createPipeline(
      pSession->get_up_seid(), fteid.teid, sourceInterface.interface_value,
      ueIpAddress.ipv4_address.s_addr, pFar);

  Logger::upf_app().info("Add Session");
  mSeidToSession[pSession->get_up_seid()] = pSession;
}

/*****************************************************************************************************************/
void SessionManager::removeBPFSession(uint64_t seid) {
  if (mSeidToSession.find(seid) == mSeidToSession.end()) {
    Logger::upf_app().error(
        "Session %d Does Not Exist. It Cannot be Removed", seid);
    throw std::runtime_error("Session Does Not Exist. It Cannot be Removed");
  }

  SessionProgramManager::getInstance().removePipeline(seid);
  Logger::upf_app().debug("Session %d Has Been Removed Successfully", seid);
}

/*****************************************************************************************************************/
bool SessionManager::comparePDR(const std::shared_ptr<pfcp::pfcp_pdr> &pFirst,
                                const std::shared_ptr<pfcp::pfcp_pdr> &pSecond){
  pfcp::precedence_t precedenceFirst, precedenceSecond;
  // TODO: Check if exists.
  pFirst->get(precedenceFirst);
  pSecond->get(precedenceSecond);
  return precedenceFirst.precedence < precedenceSecond.precedence;
}

/*****************************************************************************************************************/
void SessionManager::removeSession(uint64_t seid){
  SessionProgramManager::getInstance().remove(seid);
  Logger::upf_app().debug("Session %d has been removed", seid);
}
