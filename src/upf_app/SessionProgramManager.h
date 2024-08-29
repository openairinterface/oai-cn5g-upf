#ifndef __SESSIONPROGRAMMANAGER_H__
#define __SESSIONPROGRAMMANAGER_H__

#include <stdint.h>
#include <memory>
#include <map>
#include <pfcp_far.hpp>
#include <pfcp_qer.hpp>
#include <array>
#include <pfcp/pfcp_far.h>
#include <next_prog_rule_key.h>
#include <netinet/ether.h>

class BPFMap;
class OnStateChangeSessionProgramObserver;
class PFCP_Session_LookupProgram;
class PFCP_Session_PDR_LookupProgram;
class SessionPrograms;
class FARProgram;

/**
 * @brief This class is used to manager the PFCP Sesssion (eBPF bytecode) in
 * kernel space. It store all the BPFProgram that was loaded on the datapath.
 *
 */

struct farprograms {
  uint64_t seid;
  std::shared_ptr<FARProgram> pFARProgram;
};

class SessionProgramManager {
 public:
  /**
   * @brief Destroy the Session Program Manager object.
   *
   */
  virtual ~SessionProgramManager();

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Get the Instance object.
   *
   * @return SessionProgramManager& The unique instance.
   */
  static SessionProgramManager& getInstance();

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Set the Programs Map object.
   *
   * @param pProgramsMaps  The programs wrapper for BPF map.
   */
  void setTeidSessionMap(std::shared_ptr<BPFMap> pProgramsMaps);

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Create a new program related to the SEID.
   * The context will be empty.
   *
   * @param seid  The session identifier.
   */
  void create(uint64_t seid);

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Remove program session context.
   *
   * @param seid The session identifier.
   */
  void remove(uint64_t seid);

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Remove all programs.
   *
   */
  void removeAll();

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Set the On New Session Observer object.
   *
   * @param pObserver The observer which will be notified when a
   * PFCP_Session_PDR_LookupProgram is created.
   */
  void setOnNewSessionObserver(OnStateChangeSessionProgramObserver* pObserver);

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Find the Session Program object.
   *
   * @param seid The session identifier.
   * @return std::shared_ptr<PFCP_Session_PDR_LookupProgram> The program, which
   * represents the session.
   */
  std::shared_ptr<PFCP_Session_PDR_LookupProgram> findSessionProgram(
      uint64_t seid);

  /*---------------------------------------------------------------------------------------------------------------*/
  void addFarProgram(uint64_t seid, std::shared_ptr<FARProgram> pFARProgram);

  /*---------------------------------------------------------------------------------------------------------------*/
  void updateArpTableMap(
      std::shared_ptr<FARProgram> pFARProgram, uint32_t upfIP,
      uint32_t remoteIP);

  /*---------------------------------------------------------------------------------------------------------------*/
  uint32_t getRemoteIP(uint32_t upfIP, uint32_t remoteIP);

  /*---------------------------------------------------------------------------------------------------------------*/
  pfcp_far_t_ createFar(std::shared_ptr<pfcp::pfcp_far> pFar);

  /*---------------------------------------------------------------------------------------------------------------*/
  void createPipeline(
      uint64_t seid, uint32_t teid1, uint8_t sourceInterface,
      uint32_t ueIpAddress, std::shared_ptr<pfcp::pfcp_far> pFar,
      std::vector<std::shared_ptr<pfcp::pfcp_qer>> pQer,
      bool isModification = false, uint32_t teid2 = 0);

  /*---------------------------------------------------------------------------------------------------------------*/
  void initializeNextRuleProgIndexKey(
      next_rule_prog_index_key& key, uint32_t teid, uint32_t ueIpAddress,
      uint8_t sourceInterface);

  /*---------------------------------------------------------------------------------------------------------------*/
  void storeFarProgramIndexInNextProgRuleIndexMap(
      std::shared_ptr<FARProgram> pFARProgram,
      const next_rule_prog_index_key& key,
      std::shared_ptr<PFCP_Session_LookupProgram> pPFCP_Session_LookupProgram);

  /*---------------------------------------------------------------------------------------------------------------*/
  void storeSessionMappingMap(
      std::shared_ptr<PFCP_Session_LookupProgram> pPFCP_Session_LookupProgram,
      uint32_t ue_ip_address, uint32_t teid_dl);

  /*---------------------------------------------------------------------------------------------------------------*/
  void storeFARInFARMap(
      std::shared_ptr<FARProgram> pFARProgram,
      std::shared_ptr<pfcp::pfcp_far> pFar);

  /*---------------------------------------------------------------------------------------------------------------*/
  void saveSeidWithinFARProgram(
      uint64_t seid, std::shared_ptr<FARProgram> pFARProgram,
      const next_rule_prog_index_key& key);

  /*---------------------------------------------------------------------------------------------------------------*/
  void updateARPTableForN6(
      std::shared_ptr<FARProgram> pFARProgram, uint32_t dnIP, uint32_t upfn6IP);

  /*---------------------------------------------------------------------------------------------------------------*/
  void updateARPTableForN3(
      std::shared_ptr<FARProgram> pFARProgram, uint32_t gNodeBIP,
      uint32_t upfn3IP, uint64_t seid);

  /*---------------------------------------------------------------------------------------------------------------*/
  uint32_t getGnodebIp(std::shared_ptr<pfcp::pfcp_far> pFar);

  /*---------------------------------------------------------------------------------------------------------------*/
  void updatePipeline(
      uint64_t seid, uint32_t teid, uint32_t gNBIpAddress, bool isModification);

  /*---------------------------------------------------------------------------------------------------------------*/
  //   void storeUeQfiTeidMap(
  //       std::shared_ptr<PFCP_Session_LookupProgram>
  //       pPFCP_Session_LookupProgram, uint32_t ue_ip_address, uint8_t qfi,
  //       uint32_t teid_ul);

  /*---------------------------------------------------------------------------------------------------------------*/
  // void updateMap(std::shared_ptr<PFCP_Session_LookupProgram>
  // pPFCP_Session_LookupProgram,
  //   uint64_t seid, uint32_t teid_ul, uint32_t src_ip, uint32_t teid_dl);

  /*---------------------------------------------------------------------------------------------------------------*/
  void removePipeline(uint64_t seid);
  std::shared_ptr<SessionPrograms> findSessionPrograms(uint64_t seid);

  // std::shared_ptr<vector><struct farprograms> farPrograms;

  std::shared_ptr<std::vector<struct farprograms>> farPrograms;

 private:
  /**
   * @brief Construct a new Session Program Manager object.
   *
   */
  SessionProgramManager();
  int32_t getEmptySlot();

  // The program eBPF map.
  std::shared_ptr<BPFMap> mpTeidSessionMap;

  // The program eBPF map.
  std::shared_ptr<BPFMap> mpUeIpSessionMap;

  // The observer which will be notified when a PFCP_Session_PDR_LookupProgram
  // is created.
  OnStateChangeSessionProgramObserver* mpOnNewSessionProgramObserver;

  // The Maps to store the instance of the programs.
  std::map<uint32_t, std::shared_ptr<PFCP_Session_PDR_LookupProgram>>
      mSessionProgramMap;

  // The Maps to store the instance of the FARs programs.
  // std::map<uint32_t, std::shared_ptr<FARProgram>> mFARProgramMap;

  // The Maps to store the PFCP session deployed in datapath.
  std::map<uint32_t, std::shared_ptr<SessionPrograms>> mSessionProgramsMap;

  std::array<int64_t, 10> mProgramArray;
};

#endif  // __SESSIONPROGRAMMANAGER_H__
