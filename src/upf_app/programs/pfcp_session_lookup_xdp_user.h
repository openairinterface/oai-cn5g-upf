/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */
#ifndef __PFCP_SESSION_LOOKUP_XDP_USER_H__
#define __PFCP_SESSION_LOOKUP_XDP_USER_H__

#include <ProgramLifeCycle.hpp>
#include <atomic>
#include <linux/bpf.h>  // manage maps (e.g. bpf_update*)
#include <memory>
#include <mutex>
#include <signal.h>  // signals
#include "types.h"
#include <pfcp_session_lookup_xdp_kernel_skel.h>
#include <wrappers/BPFMap.hpp>
#include "interfaces.h"
#include <framed_routing_bpf.h>

#include "upf_config.hpp"

using namespace oai::config;
extern upf_config upf_cfg;

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
      const std::string& gtpInterface, const std::string& udpInterface,
      const upf_config& upf_cfg);
  virtual ~PFCP_Session_LookupProgram();
  void setup(bool isQosEnabled);
  std::shared_ptr<BPFMaps> getMaps();
  void tearDown();
  void create_upf_interface_map_entry(e_reference_point s);
  void removeProgramMap(uint32_t key);
  std::shared_ptr<BPFMap> getFramedRouteMappingMap();
  void updateFramedRouteMappingMap(uint32_t ue_ip, FramedRoutingKeyBPF key);
  void removeFramedRoute(FramedRoutingKeyBPF key);
  void setFramedRouting(bool enable);
  std::shared_ptr<BPFMap> getEgressInterfaceMap() const;
  std::shared_ptr<BPFMap> getArpTableMap() const;
  std::shared_ptr<BPFMap> getIfaceMap() const;
  std::shared_ptr<BPFMap> getTrafficMap() const;
  std::shared_ptr<BPFMap> getSessionMappingMap() const;
  std::shared_ptr<BPFMap> getRulesMatchPdrMap() const;
  std::shared_ptr<BPFMap> getSessionPdrsMap() const;
  std::shared_ptr<BPFMap> getSdfFilterMap() const;
  std::shared_ptr<BPFMap> getQosEnablingMap() const;
  std::shared_ptr<BPFMap> getUeQfiTeidMap() const;
  // Maps for ETH PDU session
  std::shared_ptr<BPFMap> getETHMacPduSessionMap() const;
  std::shared_ptr<BPFMap> getETHSessionMappingMap() const;
  std::shared_ptr<BPFMap> getETHRulesMatchPdrMap() const;
  std::shared_ptr<BPFMap> getETHSessionPdrsMap() const;

 private:
  void initializeMaps();
  void configurePfcpSessionLookupMaps(
      struct pfcp_session_lookup_xdp_kernel_c* skel, const upf_config& upf_cfg);
  pfcp_session_lookup_xdp_kernel_c* spSkeleton;
  std::shared_ptr<PFCP_Session_LookupProgramLifeCycle> mpLifeCycle;
  std::string mGTPInterface;
  std::string mUDPInterface;
  std::shared_ptr<BPFMaps> mpMaps;
  std::shared_ptr<BPFMap> mpTeidSessionMap;
  std::shared_ptr<BPFMap> mpSessionMappingMap;
  std::shared_ptr<BPFMap> mpEgressInterfaceMap;
  std::shared_ptr<BPFMap> mpArpTableMap;
  std::shared_ptr<BPFMap> mpUPFIfaceMap;
  std::shared_ptr<BPFMap> mpRulesMatchPdrMap;
  std::shared_ptr<BPFMap> mpSessionPdrsMap;
  std::shared_ptr<BPFMap> mpSdfFilterMap;
  std::shared_ptr<BPFMap> mpQosEnablingMap;
  std::shared_ptr<BPFMap> mpFramedRouteMappingMap;
  std::shared_ptr<BPFMap> mpFramedRouteFlagMap;

  // Maps for ETH PDU session
  std::shared_ptr<BPFMap> mpETHMacPduSessionMap;
  std::shared_ptr<BPFMap> mpETHSessionMappingMap;
  std::shared_ptr<BPFMap> mpETHRulesMatchPdrMap;
  std::shared_ptr<BPFMap> mpETHSessionPdrsMap;
};

#endif  // __PFCP_SESSION_LOOKUP_XDP_USER_H__
