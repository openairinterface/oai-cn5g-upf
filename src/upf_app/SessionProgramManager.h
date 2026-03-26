/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */
#ifndef __SESSIONPROGRAMMANAGER_H__
#define __SESSIONPROGRAMMANAGER_H__

#include <stdint.h>
#include <memory>
#include <map>
#include <pfcp_far.hpp>
#include <pfcp_qer.hpp>
#include "pfcp_pdr.hpp"
#include <array>
#include <pfcp/pfcp_far.h>
#include <pfcp/pfcp_pdr.h>
#include <pfcp/pfcp_qer.h>
#include <mac_pdu_session_key.h>
#include <session_id.h>
#include <netinet/ether.h>

class BPFMap;
class OnStateChangeSessionProgramObserver;
class PFCP_Session_LookupProgram;
class SessionPrograms;
class FARProgram;

struct pfcpprograms {
  uint64_t seid;
  std::shared_ptr<PFCP_Session_LookupProgram> pPFCP_Session_LookupProgram;
};

struct pduSessionInfo {
  uint32_t teid_ul;
  uint32_t teid_dl;
  uint32_t ueIP;
};

class SessionProgramManager {
 public:
  virtual ~SessionProgramManager();

  static SessionProgramManager& getInstance();
  void setTeidSessionMap(std::shared_ptr<BPFMap> pProgramsMaps);
  void create(uint64_t seid);
  void remove(uint64_t seid);
  void removeAll();
  void setOnNewSessionObserver(OnStateChangeSessionProgramObserver* pObserver);
  void updateArpTableMap(
      std::shared_ptr<PFCP_Session_LookupProgram> pPFCP_Session_LookupProgram,
      uint32_t upfIP, uint32_t remoteIP);
  uint32_t getRemoteIP(uint32_t upfIP, uint32_t remoteIP);
  pfcp_far_t_ createFar(std::shared_ptr<pfcp::pfcp_far> pFar);
  pfcp_pdr_t_ createPdr(std::shared_ptr<pfcp::pfcp_pdr> pPdr);
  pfcp_qer_t_ createQer(std::shared_ptr<pfcp::pfcp_qer> pQer);
  void createPipeline(std::shared_ptr<pfcp::pfcp_session> session);
  void modifyPipeline(
      std::shared_ptr<pfcp::pfcp_session> session, uint32_t teid);
  void modifyPipeline(
      std::shared_ptr<pfcp::pfcp_session> session, uint32_t teid_ul,
      uint32_t teid_dl);
  void addFramedRoutes(
      uint32_t ueIpAddress,
      const std::vector<pfcp::framed_route_t>& framedRoutes);
  void removeFramedRoutes(
      const std::vector<pfcp::framed_route_t>& framedRoutes);
  void modifyETHPipeline(
      std::shared_ptr<pfcp::pfcp_session> session, uint32_t teid_ul,
      uint32_t teid_dl);

  void createPipeline(
      uint64_t seid, uint32_t teid1, uint8_t sourceInterface,
      uint32_t ueIpAddress, std::shared_ptr<pfcp::pfcp_far> pFar,
      std::vector<std::shared_ptr<pfcp::pfcp_qer>> pQer,
      std::vector<std::shared_ptr<pfcp::pfcp_pdr>> pdrs,
      bool isModification = false, uint32_t teid2 = 0);

  void addPFCPProgram(
      uint64_t seid,
      std::shared_ptr<PFCP_Session_LookupProgram> pPFCP_Session_LookupProgram);
  void storePduSessionInMap(
      std::shared_ptr<PFCP_Session_LookupProgram> pPFCP_Session_LookupProgram,
      uint32_t ue_ip_address, uint32_t teid_dl, uint32_t teid_ul,
      uint64_t seid);
  void storeETHPduSessionInMap(
      std::shared_ptr<PFCP_Session_LookupProgram> pPFCP_Session_LookupProgram,
      uint32_t teid_ul, uint32_t teid_dl, uint32_t n3IpAddress, uint64_t seid);
  void storeFARInFARMap(
      std::shared_ptr<FARProgram> pFARProgram,
      std::shared_ptr<pfcp::pfcp_far> pFar);
  void updateARPTableForN6(
      std::shared_ptr<PFCP_Session_LookupProgram> pPFCP_Session_LookupProgram,
      uint32_t dnIP, uint32_t upfn6IP);
  void updateARPTableForN3(
      std::shared_ptr<PFCP_Session_LookupProgram> pPFCP_Session_LookupProgram,
      uint32_t gNodeBIP, uint32_t upfn3IP, uint32_t seid);
  bool getFar(
      std::shared_ptr<pfcp::pfcp_session> session,
      std::shared_ptr<pfcp::pfcp_pdr> pdr,
      std::shared_ptr<pfcp::pfcp_far>& outFar);
  bool getQer(
      std::shared_ptr<pfcp::pfcp_session> session,
      std::shared_ptr<pfcp::pfcp_pdr> pdr,
      std::shared_ptr<pfcp::pfcp_qer>& outQer);
  uint32_t getGnodebIp(std::shared_ptr<pfcp::pfcp_far> pFar);
  uint32_t retrieveGnbIp(std::shared_ptr<pfcp::pfcp_session> session);
  uint32_t retrieveUeIp(std::shared_ptr<pfcp::pfcp_session> session);
  void updatePipeline(
      uint64_t seid, uint32_t teid, uint32_t gNBIpAddress, bool isModification);
  void removePipeline(uint64_t seid);
  std::shared_ptr<SessionPrograms> findSessionPrograms(uint64_t seid);
  void sessionIds(
      session_id& key, uint64_t seid, uint32_t teid_ul, uint32_t teid_dl);

  std::shared_ptr<std::vector<struct pfcpprograms>> pfcpPrograms;

 private:
  SessionProgramManager();
  int32_t getEmptySlot();

  std::shared_ptr<BPFMap> mpTeidSessionMap;
  std::shared_ptr<BPFMap> mpUeIpSessionMap;

  // TODO [ETH-PDU] downlink map ETH PDU session info (always recorded)

  // The observer which will be notified when a PFCP_Session_PDR_LookupProgram
  // is created.
  OnStateChangeSessionProgramObserver* mpOnNewSessionProgramObserver;
  std::map<uint32_t, std::shared_ptr<SessionPrograms>> mSessionProgramsMap;
  std::array<int64_t, 10> mProgramArray;
  struct pduSessionInfo sessionInfo;
};

#endif  // __SESSIONPROGRAMMANAGER_H__
