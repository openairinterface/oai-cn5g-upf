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
#include "interfaces.h"

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
  explicit PFCP_Session_LookupProgram(
      const std::string& gtpInterface, const std::string& udpInterface);

  virtual ~PFCP_Session_LookupProgram();

  void setup(bool isQosEnabled);

  std::shared_ptr<BPFMaps> getMaps();

  void tearDown();

  // void updateProgramMap(uint32_t key, uint32_t fd);

  void create_upf_interface_map_entry(e_reference_point s);

  void removeProgramMap(uint32_t key);

  std::shared_ptr<BPFMap> getEgressInterfaceMap() const;
  std::shared_ptr<BPFMap> getArpTableMap() const;
  std::shared_ptr<BPFMap> getIfaceMap() const;
  // std::shared_ptr<BPFMap> getTeidSessionMap() const;
  // std::shared_ptr<BPFMap> getUeIpSessionMap() const;
  // std::shared_ptr<BPFMap> getNextProgRuleMap() const;
  // std::shared_ptr<BPFMap> getNextProgRuleIndexMap() const;
  std::shared_ptr<BPFMap> getTrafficMap() const;
  std::shared_ptr<BPFMap> getSessionMappingMap() const;
  std::shared_ptr<BPFMap> getRulesMatchPdrMap() const;
  std::shared_ptr<BPFMap> getSessionPdrsMap() const;
  std::shared_ptr<BPFMap> getSdfFilterMap() const;
  std::shared_ptr<BPFMap> getQosEnablingMap() const;
  std::shared_ptr<BPFMap> getUeQfiTeidMap() const;
  // std::shared_ptr<BPFMap> getQosFlowMap() const;

 private:
  void initializeMaps();

  pfcp_session_lookup_xdp_kernel_c* spSkeleton;
  std::shared_ptr<PFCP_Session_LookupProgramLifeCycle> mpLifeCycle;
  std::string mGTPInterface;
  std::string mUDPInterface;
  std::shared_ptr<BPFMaps> mpMaps;
  std::shared_ptr<BPFMap> mpTeidSessionMap;
  // std::shared_ptr<BPFMap> mpUeIpSessionMap;
  //   std::shared_ptr<BPFMap> mpNextProgRuleIndexMap;
  //   std::shared_ptr<BPFMap> mpNextProgRuleMap;
  std::shared_ptr<BPFMap> mpSessionMappingMap;
  std::shared_ptr<BPFMap> mpEgressInterfaceMap;
  std::shared_ptr<BPFMap> mpArpTableMap;
  std::shared_ptr<BPFMap> mpUPFIfaceMap;
  std::shared_ptr<BPFMap> mpRulesMatchPdrMap;
  std::shared_ptr<BPFMap> mpSessionPdrsMap;
  std::shared_ptr<BPFMap> mpSdfFilterMap;
  std::shared_ptr<BPFMap> mpQosEnablingMap;
  /*---------------------------------------------------------------------------------------------------------------*/
};

#endif  // __PFCP_SESSION_LOOKUP_XDP_USER_H__
