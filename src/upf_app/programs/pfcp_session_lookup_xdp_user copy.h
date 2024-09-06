#ifndef __PFCP_SESSION_LOOKUP_XDP_USER_H__
#define __PFCP_SESSION_LOOKUP_XDP_USER_H__

#include <ProgramLifeCycle.hpp>
#include <atomic>
#include <linux/bpf.h>  // manage maps (e.g. bpf_update*)
#include <memory>
#include <mutex>
#include <signal.h>  // signals
#include <pfcp_session_lookup_xdp_kernel_skel.h>
#include <wrappers/BPFMap.hpp>
// #include "qfi_flow_mapping_table.h"

class BPFMaps;
class BPFMap;
class SessionManager;
class RulesUtilities;

using PFCP_Session_LookupProgramLifeCycle =
    ProgramLifeCycle<pfcp_session_lookup_xdp_kernel_c>;

/**
 * @brief Singleton class to abrastract the UPF bpf program.
 */
class PFCP_Session_LookupProgram {
 public:
  /**
   * @brief Construct a new PFCP_Session_LookupProgram object.
   *
   */
  explicit PFCP_Session_LookupProgram(
      const std::string& gtpInterface, const std::string& udpInterface);

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Destroy the PFCP_Session_LookupProgram object
   */
  virtual ~PFCP_Session_LookupProgram();

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Setup the BPF program.
   *
   */
  void setup();

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Get the BPFMaps object.
   *
   * @return std::shared_ptr<BPFMaps> The reference of the BPFMaps.
   */
  std::shared_ptr<BPFMaps> getMaps();

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Tear downs the BPF program.
   *
   */
  void tearDown();

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Update program int map.
   *
   * @param key The key which will be inserted the program file descriptor.
   * @param fd The file descriptor.
   */
  void updateProgramMap(uint32_t key, uint32_t fd);

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Remove program in map.
   *
   * @param key The key which will be remove in the program map.
   */
  void removeProgramMap(uint32_t key);

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Get the TEID to session Map object.
   *
   * @return std::shared_ptr<BPFMap> The TEID to fd map.
   */
  std::shared_ptr<BPFMap> getTeidSessionMap() const;

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Get the UE IP to session Map object.
   *
   * @return std::shared_ptr<BPFMap> The UE IP to fd map.
   */
  std::shared_ptr<BPFMap> getUeIpSessionMap() const;

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Get the NextProgRule Map object.
   *
   * @return std::shared_ptr<BPFMap> The NextProgRule to fd map.
   */
  std::shared_ptr<BPFMap> getNextProgRuleMap() const;

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Get the NextProgRuleIndex Map object.
   *
   * @return std::shared_ptr<BPFMap> The pdi to index map.
   */
  std::shared_ptr<BPFMap> getNextProgRuleIndexMap() const;

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Get the Traffic Map object.
   *
   * @return std::shared_ptr<BPFMap> The TEID.
   */
  std::shared_ptr<BPFMap> getTrafficMap() const;

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Get the Session Mapping Map object.
   *
   * @return std::shared_ptr<BPFMap> mpSessionMappingMap;
   */
  std::shared_ptr<BPFMap> getSessionMappingMap() const;

  /*---------------------------------------------------------------------------------------------------------------*/
  /**
   * @brief Get the UE QFI TEID Map object.
   *
   * @return std::shared_ptr<BPFMap> mpUeQfiTeidMap;
   */
  std::shared_ptr<BPFMap> getUeQfiTeidMap() const;

  /**
   * @brief Get theQoS Flow Map object.
   *
   * @return std::shared_ptr<BPFMap> mpQosFlowMap;
   */
  std::shared_ptr<BPFMap> getQosFlowMap() const;

  /*---------------------------------------------------------------------------------------------------------------*/

 private:
  /**
   * @brief Initialize BPF wrappers maps.
   *
   */
  void initializeMaps();

  //   void instrementQfiFlowMappingTable(
  //       e_resource_type type, uint32_t qos, uint8_t qfi, uint8_t dscp);

  /*---------------------------------------------------------------------------------------------------------------*/
  // The reference of the bpf maps.
  std::shared_ptr<BPFMaps> mpMaps;

  /*---------------------------------------------------------------------------------------------------------------*/
  // The skeleton of the UPF program generated by bpftool.
  // ProgramLifeCycle is the owner of the pointer.
  pfcp_session_lookup_xdp_kernel_c* spSkeleton;

  /*---------------------------------------------------------------------------------------------------------------*/
  // The program eBPF map.
  std::shared_ptr<BPFMap> mpTeidSessionMap;

  /*---------------------------------------------------------------------------------------------------------------*/
  // The program eBPF map.
  std::shared_ptr<BPFMap> mpUeIpSessionMap;

  /*---------------------------------------------------------------------------------------------------------------*/
  // The pdi key to program index map.
  std::shared_ptr<BPFMap> mpNextProgRuleIndexMap;

  /*---------------------------------------------------------------------------------------------------------------*/
  // The next prog rule map.
  std::shared_ptr<BPFMap> mpNextProgRuleMap;

  /*---------------------------------------------------------------------------------------------------------------*/
  // The traffic map.
  // std::shared_ptr<BPFMap> mpTrafficMap;

  /*---------------------------------------------------------------------------------------------------------------*/
  // The session mapping map.
  std::shared_ptr<BPFMap> mpSessionMappingMap;

  /*---------------------------------------------------------------------------------------------------------------*/

  // The UE-QFI-TEID map.
  // std::shared_ptr<BPFMap> mpUeQfiTeidMap;

  /*---------------------------------------------------------------------------------------------------------------*/

  // The QOS Flow map.
  // std::shared_ptr<BPFMap> mpQosFlowMap;

  /*---------------------------------------------------------------------------------------------------------------*/
  // The BPF lifecycle program.
  std::shared_ptr<PFCP_Session_LookupProgramLifeCycle> mpLifeCycle;

  /*---------------------------------------------------------------------------------------------------------------*/
  // The GTP interface.
  std::string mGTPInterface;

  /*---------------------------------------------------------------------------------------------------------------*/
  // The UDP interface.
  std::string mUDPInterface;
  /*---------------------------------------------------------------------------------------------------------------*/
};

#endif  // __PFCP_SESSION_LOOKUP_XDP_USER_H__
