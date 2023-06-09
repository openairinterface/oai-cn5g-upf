#include "pfcp_session_pdr_lookup_ebpf_xdp_prgrm_user.h"
#include <SessionManager.h>
#include <bpf/bpf.h>     // bpf calls
#include <bpf/libbpf.h>  // bpf wrappers
#include <iostream>      // cout
#include <stdexcept>     // exception
// // #include <utils/LogDefines.h>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "interfaces.h"
#include "upf_config.hpp"
#include "logger.hpp"

using namespace upf;
// upf_config upf_cfg;

/*****************************************************************************************************************/
PFCP_Session_PDR_LookupProgram::PFCP_Session_PDR_LookupProgram(const std::string& gtpInterface, const std::string& udpInterface)
 : mGTPInterface(gtpInterface), mUDPInterface(udpInterface) {

 // // __builtin_memset(&gtp_interface, 0, sizeof(struct interface));
 // // __builtin_memset(&udp_interface, 0, sizeof(struct interface));

 // // if(mUDPInterface.empty() || mGTPInterface.empty()){
 // //   LOG_ERROR("GTP and/or UDP interface(s) are not defined!");
 // //   throw std::runtime_error("GTP and/or UDP interface(s) are not defined!");
 // // }
  
 // // gtp_interface.ipv4_address = atoi((conv::toString(upf_cfg.n3.addr4)).c_str());
 // // LOG_DBG(".......................GTP Interface: %d\n", upf_cfg.n3.addr4.s_addr);
 // // LOG_DBG("    Interface ipv4.addr ........: %s", inet_ntoa(upf_cfg.n3.addr4));
 // // udp_interface.ipv4_address = atoi((conv::toString(upf_cfg.n6.addr4)).c_str());

 // // LOG_DBG("GTP Interface: %s, IF_NAME: %d, IPv4: %d \n", gtp_interface.if_name, gtp_interface.ipv4_address);
 // // LOG_DBG("UDP Interface: %s, IF_NAME: %d, IPv4: %d \n", udp_interface.if_name, udp_interface.ipv4_address);
  
  mpLifeCycle = std::make_shared<PFCP_Session_PDR_LookupProgramLifeCycle>(
                                                      pfcp_session_pdr_lookup_ebpf_xdp_prgrm_kernel_c__open, \
                                                      pfcp_session_pdr_lookup_ebpf_xdp_prgrm_kernel_c__load, \
                                                      pfcp_session_pdr_lookup_ebpf_xdp_prgrm_kernel_c__attach, \
                                                      pfcp_session_pdr_lookup_ebpf_xdp_prgrm_kernel_c__destroy
                                                      );
}

/*****************************************************************************************************************/
PFCP_Session_PDR_LookupProgram::~PFCP_Session_PDR_LookupProgram() {
}

/*****************************************************************************************************************/
void PFCP_Session_PDR_LookupProgram::setup() {

  // LOG_DBG("Saving Interfaces in Map");
  // auto gtpInterface = UserPlaneComponent::getInstance().getGTPInterface();
  // auto udpInterface = UserPlaneComponent::getInstance().getUDPInterface();

  // uint32_t gtpInterfaceIndex = if_nametoindex(gtpInterface.c_str());
  // uint32_t udpInterfaceIndex = if_nametoindex(udpInterface.c_str());

  // mpIfaceMap->update(gtpInterfaceIndex, gtp_interface.ipv4_address, BPF_ANY);
  // mpIfaceMap->update(udpInterfaceIndex, udp_interface.ipv4_address, BPF_ANY);

  spSkeleton = mpLifeCycle->open();
  initializeMaps();
  mpLifeCycle->load();
  mpLifeCycle->attach();
  // Entry point interface
  if (mUDPInterface.empty() || mGTPInterface.empty()) {
    // LOG_ERROR("GTP or UDP interface not defined!");
    Logger::upf_app().error("GTP or UDP interface not defined!");
    throw std::runtime_error("GTP or UDP interface not defined!");
  }
  // LOG_DBG("Link UDP interface to interface {}", mUDPInterface.c_str())
  Logger::upf_app().debug(
      "Link UDP interface to interface %s", mUDPInterface.c_str());
  mpLifeCycle->link("xdp_entry_point", mUDPInterface.c_str());
  // LOG_DBG("Link GTP interface to interface {}", mGTPInterface.c_str())
  Logger::upf_app().debug(
      "Link GTP interface to interface %s", mGTPInterface.c_str());
  mpLifeCycle->link("xdp_entry_point", mGTPInterface.c_str());
}

/*****************************************************************************************************************/
std::shared_ptr<BPFMaps> PFCP_Session_PDR_LookupProgram::getMaps() {
  return mpMaps;
}

/*****************************************************************************************************************/
// TODO: Check when kill when running.
// It was noted the infinity loop.
void PFCP_Session_PDR_LookupProgram::tearDown() {
  mpLifeCycle->tearDown();
}

/*****************************************************************************************************************/
void PFCP_Session_PDR_LookupProgram::updateProgramMap(uint32_t key, uint32_t fd) {
  mpTeidSessionMap->update(key, fd, BPF_ANY);
}

/*****************************************************************************************************************/
void PFCP_Session_PDR_LookupProgram::removeProgramMap(uint32_t key) {
  s32 fd;
  // Remove only if exists.
  if (mpTeidSessionMap->lookup(key, &fd) == 0) {
    mpTeidSessionMap->remove(key);
  }
}

/*****************************************************************************************************************/
std::shared_ptr<BPFMap> PFCP_Session_PDR_LookupProgram::getTeidSessionMap() const {
  return mpTeidSessionMap;
}

/*****************************************************************************************************************/
std::shared_ptr<BPFMap> PFCP_Session_PDR_LookupProgram::getUeIpSessionMap() const {
  return mpUeIpSessionMap;
}

/*****************************************************************************************************************/
std::shared_ptr<BPFMap> PFCP_Session_PDR_LookupProgram::getNextProgRuleMap() const {
  return mpNextProgRuleMap;
}

/*****************************************************************************************************************/
std::shared_ptr<BPFMap> PFCP_Session_PDR_LookupProgram::getNextProgRuleIndexMap() const {
  return mpNextProgRuleIndexMap;
}

/*****************************************************************************************************************/
std::shared_ptr<BPFMap> PFCP_Session_PDR_LookupProgram::getIfaceMap() const {
  return mpIfaceMap;
}

/*****************************************************************************************************************/
void PFCP_Session_PDR_LookupProgram::initializeMaps() {
  // Store all maps available in the program.
  mpMaps = std::make_shared<BPFMaps>(mpLifeCycle->getBPFSkeleton()->skeleton);

  // Warning - The name of the map must be the same of the BPF program.
  mpTeidSessionMap = std::make_shared<BPFMap>(mpMaps->getMap("m_teid_session"));
  mpUeIpSessionMap = std::make_shared<BPFMap>(mpMaps->getMap("m_ueip_session"));
  mpNextProgRuleMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_next_rule_prog"));
  mpNextProgRuleIndexMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_next_rule_prog_index"));
  mpIfaceMap = std::make_shared<BPFMap>(mpMaps->getMap("m_iface"));
}
/*****************************************************************************************************************/