/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */
#ifndef __SESSIONMANAGER_H__
#define __SESSIONMANAGER_H__

#include <UserPlaneComponent.h>
#include <ie/fseid.h>
#include <ie/pdr_id.h>
// #include <interfaces/RulesUtilities.h>
#include <memory>
#include <pfcp/pfcp_far.h>
#include <pfcp/pfcp_pdr.h>
#include <pfcp/pfcp_pdrs.h>
#include <pfcp/pfcp_session.h>
#include <vector>
#include <wrappers/BPFMap.hpp>

#include <msg_pfcp.hpp>
#include "3gpp_29.244.hpp"
#include <pfcp_session.hpp>
#include <unordered_map>

#include "itti_msg_n4.hpp"

class BPFMap;
// class ForwardingActionRules;
// class PacketDetectionRules;
class SessionBpf;

class SessionManager {
  enum class Direction { Uplink, Downlink };

 public:
  SessionManager();
  virtual ~SessionManager();
  void removeSession(uint64_t seid);

  void createBpfSession(
      std::shared_ptr<pfcp::pfcp_session> pSession,
      itti_n4_session_establishment_request* est_req,
      itti_n4_session_modification_request* mod_req,
      itti_n4_session_deletion_request* del_req);

  void updateBpfSession(
      std::shared_ptr<pfcp::pfcp_session> pSession,
      itti_n4_session_establishment_request* est_req,
      itti_n4_session_modification_request* mod_req,
      itti_n4_session_deletion_request* del_req);

  void modifyBpfSession(
      std::shared_ptr<pfcp::pfcp_session> session,
      itti_n4_session_establishment_request* est_req,
      itti_n4_session_modification_request* mod_req,
      itti_n4_session_deletion_request* del_req);

  void removeBpfSession(
      std::shared_ptr<pfcp::pfcp_session> pSession,
      itti_n4_session_establishment_request* est_req,
      itti_n4_session_modification_request* mod_req,
      itti_n4_session_deletion_request* del_req);

  void createBPFSessionUL(
      std::shared_ptr<pfcp::pfcp_session> pSession,
      std::shared_ptr<pfcp::pfcp_pdr> pdrHighPrecedenceUl);

  void createBPFSessionDL(
      std::shared_ptr<pfcp::pfcp_session> pSession,
      std::shared_ptr<pfcp::pfcp_pdr> pdrHighPrecedenceDl);

  void updateBPFSessionUL(
      std::shared_ptr<pfcp::pfcp_session> pSession,
      std::shared_ptr<pfcp::pfcp_pdr> pdrHighPrecedenceUl);

  void updateBPFSessionDL(
      std::shared_ptr<pfcp::pfcp_session> pSession,
      std::shared_ptr<pfcp::pfcp_pdr> pdrHighPrecedenceDl);

  void processPDRDetails(
      std::shared_ptr<pfcp::pfcp_session> pSession,
      std::shared_ptr<pfcp::pfcp_pdr> pdrHighPrecedence);

  void processPDRs(std::shared_ptr<pfcp::pfcp_session> pSession_establishment);

  void sortPDRs(std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdr);

  void prepareEbpfSession(
      std::shared_ptr<pfcp::pfcp_session> pSession_establishment,
      std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs);

  /*****************************************************************************************************************/
  bool extractPdi(std::shared_ptr<pfcp::pfcp_pdr> pdr, pfcp::pdi& pdi);

  /*****************************************************************************************************************/
  bool extractSourceIface(
      pfcp::pdi& pdi, pfcp::source_interface_t& sourceInterface);

  /*****************************************************************************************************************/
  bool extractUeIpv4(pfcp::pdi& pdi, pfcp::ue_ip_address_t& ueIpAddress);

  /*****************************************************************************************************************/
  bool extractEthernetPduSessionInformation(
      pfcp::pdi& pdi,
      pfcp::ethernet_pdu_session_information_t& ethernetPduSessionInformation);

  /*****************************************************************************************************************/
  bool extractEthernetPacketFilter(
      pfcp::pdi& pdi, pfcp::ethernet_packet_filter& ethernetPacketFilter);

  /*---------------------------------------------------------------------------------------------------------------*/
  bool getFar(
      std::shared_ptr<pfcp::pfcp_session> session,
      std::shared_ptr<pfcp::pfcp_pdr> pdr,
      std::shared_ptr<pfcp::pfcp_far>& outFar);

  bool getQer(
      std::shared_ptr<pfcp::pfcp_session> session,
      std::shared_ptr<pfcp::pfcp_pdr> pdr,
      std::shared_ptr<pfcp::pfcp_qer>& outQer);

  uint32_t retrieveTeid(std::shared_ptr<pfcp::pfcp_session> session);

  uint64_t findUplinkTeid(
      uint64_t seid,
      const std::vector<std::shared_ptr<pfcp::pfcp_session>>& sessions);
  uint64_t findUplinkTeid(const std::shared_ptr<pfcp::pfcp_session> session);

  static bool comparePDR(
      const std::shared_ptr<pfcp::pfcp_pdr>& first,
      const std::shared_ptr<pfcp::pfcp_pdr>& second);

  void categorizePDRs(std::shared_ptr<pfcp::pfcp_session> session);

  std::shared_ptr<pfcp::pfcp_qer> findQER(
      std::shared_ptr<pfcp::pfcp_session> session, uint32_t qer_id);

  void setupEbpfPipeline(
      std::shared_ptr<pfcp::pfcp_session> session,
      std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs, Direction direction);

  std::vector<std::shared_ptr<pfcp::pfcp_session>> sessions;

  std::unordered_map<uint64_t, std::shared_ptr<pfcp::pfcp_session>>
      mSeidToSession;
};

#endif  // __SESSIONMANAGER_H__
