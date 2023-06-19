#include "pfcp_session_lookup_ebpf_xdp_prgrm_user.h"
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
extern upf_config upf_cfg;

/*****************************************************************************************************************/
PFCP_Session_LookupProgram::PFCP_Session_LookupProgram(
    const std::string& gtpInterface, const std::string& udpInterface)
    : mGTPInterface(gtpInterface), mUDPInterface(udpInterface) {
  // // __builtin_memset(&gtp_interface, 0, sizeof(struct interface));
  // // __builtin_memset(&udp_interface, 0, sizeof(struct interface));

  // // if(mUDPInterface.empty() || mGTPInterface.empty()){
  // //   LOG_ERROR("GTP and/or UDP interface(s) are not defined!");
  // //   throw std::runtime_error("GTP and/or UDP interface(s) are not
  // defined!");
  // // }

  // // gtp_interface.ipv4_address =
  // atoi((conv::toString(upf_cfg.n3.addr4)).c_str());
  // // LOG_DBG(".......................GTP Interface: %d\n",
  // upf_cfg.n3.addr4.s_addr);
  // // LOG_DBG("    Interface ipv4.addr ........: %s",
  // inet_ntoa(upf_cfg.n3.addr4));
  // // udp_interface.ipv4_address =
  // atoi((conv::toString(upf_cfg.n6.addr4)).c_str());

  // // LOG_DBG("GTP Interface: %s, IF_NAME: %d, IPv4: %d \n",
  // gtp_interface.if_name, gtp_interface.ipv4_address);
  // // LOG_DBG("UDP Interface: %s, IF_NAME: %d, IPv4: %d \n",
  // udp_interface.if_name, udp_interface.ipv4_address);

  mpLifeCycle = std::make_shared<PFCP_Session_LookupProgramLifeCycle>(
      pfcp_session_lookup_ebpf_xdp_prgrm_kernel_c__open,
      pfcp_session_lookup_ebpf_xdp_prgrm_kernel_c__load,
      pfcp_session_lookup_ebpf_xdp_prgrm_kernel_c__attach,
      pfcp_session_lookup_ebpf_xdp_prgrm_kernel_c__destroy);
}

/*****************************************************************************************************************/
PFCP_Session_LookupProgram::~PFCP_Session_LookupProgram() {}

/*****************************************************************************************************************/
void PFCP_Session_LookupProgram::create_upf_interface_map_entry(
    e_reference_point s) {
  struct s_interface iface;
  __builtin_memset(&iface, 0, sizeof(s_interface));

  switch (s) {
    case N3_INTERFACE:
      iface.ipv4_address = upf_cfg.n3.addr4.s_addr;
      iface.port         = upf_cfg.n3.port;
      iface.if_name      = (upf_cfg.n3.if_name).c_str();
      getIfaceMap()->update(s, iface, BPF_ANY);
      Logger::upf_app().info("Reference Point N3 Added to m_upf_interface Map");
      break;
    case N6_INTERFACE:
      iface.ipv4_address = upf_cfg.n6.addr4.s_addr;
      iface.port         = upf_cfg.n6.port;
      iface.if_name      = (upf_cfg.n6.if_name).c_str();
      getIfaceMap()->update(s, iface, BPF_ANY);
      Logger::upf_app().info("Reference Point N6 Added to m_upf_interface Map");
      break;
    case N4_INTERFACE:
      iface.ipv4_address = upf_cfg.n4.addr4.s_addr;
      iface.port         = upf_cfg.n4.port;
      iface.if_name      = (upf_cfg.n4.if_name).c_str();
      getIfaceMap()->update(s, iface, BPF_ANY);
      Logger::upf_app().info("Reference Point N4 Added to m_upf_interface Map");
      break;
    case N9_INTERFACE:
      Logger::upf_app().error("Reference Point N9 Not Defined");
      break;
    case N19_INTERFACE:
      Logger::upf_app().error("Reference Point N19 Not Defined");
      break;
    default:
      Logger::upf_app().error("The Reference Point is Not Defined");
  }
}
/*****************************************************************************************************************/
void PFCP_Session_LookupProgram::setup() {
  spSkeleton = mpLifeCycle->open();
  initializeMaps();
  mpLifeCycle->load();
  mpLifeCycle->attach();
  // Entry point interface
  if (mUDPInterface.empty() || mGTPInterface.empty()) {
    Logger::upf_app().error("GTP or UDP interface not defined!");
    throw std::runtime_error("GTP or UDP interface not defined!");
  }

  Logger::upf_app().debug(
      "Link UDP interface to interface %s", mUDPInterface.c_str());
  mpLifeCycle->link("xdp_entry_point", mUDPInterface.c_str());

  Logger::upf_app().debug(
      "Link GTP interface to interface %s", mGTPInterface.c_str());
  mpLifeCycle->link("xdp_entry_point", mGTPInterface.c_str());

  Logger::upf_app().debug("Adding Reference Points to m_upf_interface Map:");
  create_upf_interface_map_entry(N3_INTERFACE);
  create_upf_interface_map_entry(N6_INTERFACE);
  create_upf_interface_map_entry(N4_INTERFACE);
}

/*****************************************************************************************************************/
std::shared_ptr<BPFMaps> PFCP_Session_LookupProgram::getMaps() {
  return mpMaps;
}

/*****************************************************************************************************************/
// TODO: Check when kill when running.
// It was noted the infinity loop.
void PFCP_Session_LookupProgram::tearDown() {
  mpLifeCycle->tearDown();
}

/*****************************************************************************************************************/
void PFCP_Session_LookupProgram::updateProgramMap(uint32_t key, uint32_t fd) {
  mpTeidSessionMap->update(key, fd, BPF_ANY);
}

/*****************************************************************************************************************/
void PFCP_Session_LookupProgram::removeProgramMap(uint32_t key) {
  s32 fd;
  // Remove only if exists.
  if (mpTeidSessionMap->lookup(key, &fd) == 0) {
    mpTeidSessionMap->remove(key);
  }
}

/*****************************************************************************************************************/
std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getTeidSessionMap() const {
  return mpTeidSessionMap;
}

/*****************************************************************************************************************/
std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getUeIpSessionMap() const {
  return mpUeIpSessionMap;
}

/*****************************************************************************************************************/
std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getNextProgRuleMap() const {
  return mpNextProgRuleMap;
}

/*****************************************************************************************************************/
std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getNextProgRuleIndexMap()
    const {
  return mpNextProgRuleIndexMap;
}

/*****************************************************************************************************************/
std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getIfaceMap() const {
  return mpUPFIfaceMap;
}

/*****************************************************************************************************************/
void PFCP_Session_LookupProgram::initializeMaps() {
  // Store all maps available in the program.
  mpMaps = std::make_shared<BPFMaps>(mpLifeCycle->getBPFSkeleton()->skeleton);

  // Warning - The name of the map must be the same of the BPF program.
  mpTeidSessionMap = std::make_shared<BPFMap>(mpMaps->getMap("m_teid_session"));
  mpUeIpSessionMap = std::make_shared<BPFMap>(mpMaps->getMap("m_ueip_session"));
  mpNextProgRuleMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_next_rule_prog"));
  mpNextProgRuleIndexMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_next_rule_prog_index"));
  mpUPFIfaceMap = std::make_shared<BPFMap>(mpMaps->getMap("m_upf_interfaces"));
}
/*****************************************************************************************************************/