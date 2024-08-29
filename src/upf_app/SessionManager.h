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

// FIXME: This class compose the UserPlaneComponent. When the program is
// deleted, this class must be updated.

// TODO: SessionRequestHandler? SessionMessageHandler?

// TODO: Decouple PDR and FAR management.

/**
 * @brief This class abstracts the communication to manager the session BPF
 * maps. It communicate with BPF maps in order to update its PDRs and FARs. This
 * class does not validate the input.
 */

class SessionManager {
 public:
  // Set of PDRs.

  // using pdrs_t = std::vector<std::shared_ptr<PacketDetectionRules>>;
  /*---------------------------------------------------------------------------------------------------------------*/

  /**
   * @brief Construct a new Session Manager object.
   *
   */
  SessionManager();

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Destroy the Session Manager object.
   *
   */
  virtual ~SessionManager();

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Create a Session object in BPF map.
   *
   * @param pSession The session object to be created.
   */
  void createSession(std::shared_ptr<SessionBpf> pSession);
  /*---------------------------------------------------------------------------------------------------------------*/

  /**
   * @brief Remove a session object from BPF map.
   *
   * @param seid The session endpoint identifier representing the session to be
   * removed.
   */
  void removeSession(uint64_t seid);

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief  Creates BPF pipeline.
   *
   * @param pSession The PFCP session which contains the context that will be
   * deployed.
   */
  void createBPFSession(
      std::shared_ptr<pfcp::pfcp_session> pSession,
      itti_n4_session_establishment_request* est_req,
      itti_n4_session_modification_request* mod_req,
      itti_n4_session_deletion_request* del_req);
  /*---------------------------------------------------------------------------------------------------------------*/

  /**
   * @brief Update a Session object in BPF map.
   *
   * @param pSession The session object to be updated.
   */
  void updateBPFSession(
      std::shared_ptr<pfcp::pfcp_session> pSession,
      itti_n4_session_establishment_request* est_req,
      itti_n4_session_modification_request* mod_req,
      itti_n4_session_deletion_request* del_req);

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Remove BPF pipeline.
   *
   * @param seid  The PFCP session which contains the context that will be
   * removed.
   */
  void removeBPFSession(
      std::shared_ptr<pfcp::pfcp_session> pSession,
      itti_n4_session_establishment_request* est_req,
      itti_n4_session_modification_request* mod_req,
      itti_n4_session_deletion_request* del_req);

  /*---------------------------------------------------------------------------------------------------------------*/
  void createBPFSessionUL(
      std::shared_ptr<pfcp::pfcp_session> pSession,
      std::shared_ptr<pfcp::pfcp_pdr> pdrHighPrecedenceUl);

  /*---------------------------------------------------------------------------------------------------------------*/
  void createBPFSessionDL(
      std::shared_ptr<pfcp::pfcp_session> pSession,
      std::shared_ptr<pfcp::pfcp_pdr> pdrHighPrecedenceDl);

  /*---------------------------------------------------------------------------------------------------------------*/
  void updateBPFSessionUL(
      std::shared_ptr<pfcp::pfcp_session> pSession,
      std::shared_ptr<pfcp::pfcp_pdr> pdrHighPrecedenceUl);

  /*---------------------------------------------------------------------------------------------------------------*/
  void updateBPFSessionDL(
      std::shared_ptr<pfcp::pfcp_session> pSession,
      std::shared_ptr<pfcp::pfcp_pdr> pdrHighPrecedenceDl);

  /*****************************************************************************************************************/
  void processPDRDetails(
      std::shared_ptr<pfcp::pfcp_session> pSession,
      std::shared_ptr<pfcp::pfcp_pdr> pdrHighPrecedence, int interfaceValue,
      const std::string& direction);

  /*****************************************************************************************************************/
  /**
   * @brief Process PDRs to populate uplink and downlink vectors
   * @param std::shared_ptr<pfcp::pfcp_session>
   */
  void processPDRs(std::shared_ptr<pfcp::pfcp_session> pSession_establishment);

  /*****************************************************************************************************************/
  /**
   * @brief Sort uplink and downlink vectors
   * @param std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs_uplink
   * @param std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs_downlink
   */
  void sortPDRs(
      std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs_uplink,
      std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs_downlink);

  /*****************************************************************************************************************/
  /**
   * @brief Create BPF session for specific direction
   * @param std::shared_ptr<pfcp::pfcp_session> pSession_establishment
   * @param std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs
   * @param const std::string& direction
   */
  void createSessionDirection(
      std::shared_ptr<pfcp::pfcp_session> pSession_establishment,
      std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs,
      const std::string& direction);

  /*****************************************************************************************************************/
  bool extractPdi(std::shared_ptr<pfcp::pfcp_pdr> pdr, pfcp::pdi& pdi);

  /*****************************************************************************************************************/
  bool extractSourceIface(
      pfcp::pdi& pdi, pfcp::source_interface_t& sourceInterface);

  /*****************************************************************************************************************/
  bool extractUeIpv4(pfcp::pdi& pdi, pfcp::ue_ip_address_t& ueIpAddress);

  /*---------------------------------------------------------------------------------------------------------------*/
  bool extractFar(
      std::shared_ptr<pfcp::pfcp_pdr> pdr,
      std::shared_ptr<pfcp::pfcp_session> session,
      std::shared_ptr<pfcp::pfcp_far>& outFar);

  /*---------------------------------------------------------------------------------------------------------------*/
  bool extractQer(
      std::shared_ptr<pfcp::pfcp_pdr> pdr,
      std::shared_ptr<pfcp::pfcp_session> session,
      std::vector<std::shared_ptr<pfcp::pfcp_qer>>* outQer);

  /*---------------------------------------------------------------------------------------------------------------*/
  bool extractForwardingParams(
      std::shared_ptr<pfcp::pfcp_far> far,
      pfcp::forwarding_parameters& forwardingParams);

  /*---------------------------------------------------------------------------------------------------------------*/
  uint64_t findUplinkTeid(
      uint64_t seid,
      const std::vector<std::shared_ptr<pfcp::pfcp_session>>& sessions);

  /*---------------------------------------------------------------------------------------------------------------*/
  static bool comparePDR(
      const std::shared_ptr<pfcp::pfcp_pdr>& first,
      const std::shared_ptr<pfcp::pfcp_pdr>& second);

  std::vector<std::shared_ptr<pfcp::pfcp_session>> sessions;

  /*---------------------------------------------------------------------------------------------------------------*/
  std::unordered_map<uint64_t, std::shared_ptr<pfcp::pfcp_session>>
      mSeidToSession;
};

#endif  // __SESSIONMANAGER_H__
