#include "pfcp_session_lookup_xdp_user.h"
#include <SessionManager.h>
#include <bpf/bpf.h>     // bpf calls
#include <bpf/libbpf.h>  // bpf wrappers
#include <iostream>      // cout
#include <stdexcept>     // exception
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "interfaces.h"
#include "logger.hpp"
#include "upf_config.hpp"

using namespace oai::config;
extern upf_config upf_cfg;

class XDPSection {
 public:
  static constexpr const char* Uplink   = "xdp_handle_uplink";
  static constexpr const char* Downlink = "xdp_handle_downlink";
  static constexpr const char* Shaping  = "xdp_handle_shaping";
};

/*---------------------------------------------------------------------------------------------------------------*/
int is_little_endian2() {
  u32 value = 1;
  u8* byte  = (u8*) &value;
  return (*byte == 1);
}

/*---------------------------------------------------------------------------------------------------------------*/
PFCP_Session_LookupProgram::PFCP_Session_LookupProgram(
    const std::string& gtpInterface, const std::string& udpInterface)
    : mGTPInterface(gtpInterface), mUDPInterface(udpInterface) {
  mpLifeCycle = std::make_shared<PFCP_Session_LookupProgramLifeCycle>(
      pfcp_session_lookup_xdp_kernel_c__open,
      pfcp_session_lookup_xdp_kernel_c__load,
      pfcp_session_lookup_xdp_kernel_c__attach,
      pfcp_session_lookup_xdp_kernel_c__destroy);
}

/*---------------------------------------------------------------------------------------------------------------*/
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

/*---------------------------------------------------------------------------------------------------------------*/
PFCP_Session_LookupProgram::~PFCP_Session_LookupProgram() {}

/*---------------------------------------------------------------------------------------------------------------*/
void PFCP_Session_LookupProgram::setup(bool isQosEnabled) {
  spSkeleton = mpLifeCycle->open();
  initializeMaps();
  mpLifeCycle->load();
  mpLifeCycle->attach();

  Logger::upf_app().debug("Configure redirect interface");
  auto udpInterface = UserPlaneComponent::getInstance().getUDPInterface();
  auto gtpInterface = UserPlaneComponent::getInstance().getGTPInterface();

  uint32_t udpInterfaceIndex = if_nametoindex(udpInterface.c_str());
  uint32_t gtpInterfaceIndex = if_nametoindex(gtpInterface.c_str());
  uint32_t uplinkId          = static_cast<uint32_t>(FlowDirection::UPLINK);
  uint32_t downlinkId        = static_cast<uint32_t>(FlowDirection::DOWNLINK);

  mpEgressInterfaceMap->update(uplinkId, udpInterfaceIndex, BPF_ANY);
  mpEgressInterfaceMap->update(downlinkId, gtpInterfaceIndex, BPF_ANY);

  Logger::upf_app().debug("Adding Reference Points to m_upf_interface Map");
  create_upf_interface_map_entry(N3_INTERFACE);
  create_upf_interface_map_entry(N6_INTERFACE);
  create_upf_interface_map_entry(N4_INTERFACE);

  // Entry point interface
  if (mUDPInterface.empty() || mGTPInterface.empty()) {
    Logger::upf_app().error("GTP or UDP interface not defined!");
    throw std::runtime_error("GTP or UDP interface not defined!");
  }

  Logger::upf_app().debug(
      "Link GTP XDP Section to interface %s", mGTPInterface.c_str());
  mpLifeCycle->link(XDPSection::Uplink, mGTPInterface.c_str());

  Logger::upf_app().debug(
      "Link Non-GTP XDP Section to interface %s", mUDPInterface.c_str());
  if (isQosEnabled) {
    Logger::upf_app().debug(
        "QoS enforcement is enabled in the configuration. A TC BPF section is "
        "created ");
    mpLifeCycle->link(XDPSection::Shaping, mUDPInterface.c_str());
  } else {
    Logger::upf_app().debug(
        "QoS enforcement is disabled in the configuration.");
    mpLifeCycle->link(XDPSection::Downlink, mUDPInterface.c_str());
  }
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMaps> PFCP_Session_LookupProgram::getMaps() {
  return mpMaps;
}

/*---------------------------------------------------------------------------------------------------------------*/
// TODO: Check when kill when running.
// It was noted the infinity loop.
void PFCP_Session_LookupProgram::tearDown() {
  mpLifeCycle->unpin_maps();
  mpLifeCycle->tearDown();
}

/*---------------------------------------------------------------------------------------------------------------*/
void PFCP_Session_LookupProgram::removeProgramMap(uint32_t key) {
  s32 fd;
  // Remove only if exists.
  if (mpTeidSessionMap->lookup(key, &fd) == 0) {
    mpTeidSessionMap->remove(key);
  }
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getSessionMappingMap()
    const {
  return mpSessionMappingMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getEgressInterfaceMap()
    const {
  return mpEgressInterfaceMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getArpTableMap() const {
  return mpArpTableMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getIfaceMap() const {
  return mpUPFIfaceMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getRulesMatchPdrMap()
    const {
  return mpRulesMatchPdrMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getSessionPdrsMap() const {
  return mpSessionPdrsMap;
}

/*---------------------------------------------------------------------------------------------------------------*/

std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getSdfFilterMap() const {
  return mpSdfFilterMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getQosEnablingMap() const {
  return mpQosEnablingMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getFramedRouteMappingMap() {
  return mpFramedRouteMappingMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
void PFCP_Session_LookupProgram::updateFramedRouteMappingMap(
    uint32_t ue_ip, FramedRoutingKeyBPF key) {
  uint32_t hash_key = hash_framed_routing_key(&key);
  Logger::upf_app().debug(
      "Update framed routing map with key: %u, value: %u", hash_key, ue_ip);
  mpFramedRouteMappingMap->update(hash_key, ue_ip, BPF_ANY);
}

/*---------------------------------------------------------------------------------------------------------------*/
void PFCP_Session_LookupProgram::removeFramedRoute(FramedRoutingKeyBPF key) {
  uint32_t hash_key = hash_framed_routing_key(&key);
  uint32_t ueip;
  if (mpFramedRouteMappingMap->lookup(hash_key, &ueip) == 0) {
    mpFramedRouteMappingMap->remove(hash_key);
  }
}

void PFCP_Session_LookupProgram::setFramedRouting(bool enable) {
  uint8_t value = (enable) ? 1 : 0;
  uint8_t key   = 0;
  mpFramedRouteFlagMap->update(key, value, BPF_ANY);
}

// ---------------------------------------------------------------------------------------------------------------*/
// For ETH PDU session
std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getETHMacPduSessionMap() const {
  return mpETHMacPduSessionMap;
}

std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getETHSessionMappingMap()
    const {
  return mpETHSessionMappingMap;
}

std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getETHRulesMatchPdrMap()
    const {
  return mpETHRulesMatchPdrMap;
}

std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getETHSessionPdrsMap()
    const {
  return mpETHSessionPdrsMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
void PFCP_Session_LookupProgram::initializeMaps() {
  // Store all maps available in the program.
  mpMaps = std::make_shared<BPFMaps>(mpLifeCycle->getBPFSkeleton()->skeleton);

  mpSessionMappingMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_session_mapping"));
  mpArpTableMap = std::make_shared<BPFMap>(mpMaps->getMap("m_arp_table"));
  mpEgressInterfaceMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_redirect_interfaces"));
  mpUPFIfaceMap = std::make_shared<BPFMap>(mpMaps->getMap("m_upf_interfaces"));
  mpSessionPdrsMap = std::make_shared<BPFMap>(mpMaps->getMap("m_session_pdrs"));
  mpRulesMatchPdrMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_rules_match_pdr"));

  mpSdfFilterMap = std::make_shared<BPFMap>(mpMaps->getMap("m_sdf_filter"));

  mpQosEnablingMap = std::make_shared<BPFMap>(mpMaps->getMap("m_qos_enabling"));
  mpFramedRouteMappingMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_framed_route_mapping"));
  mpFramedRouteFlagMap =
      std::make_shared<BPFMap>(mpMaps->getMap("framed_routing_flag"));

  // Maps for ETH PDU session
  mpETHMacPduSessionMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_mac_pdu_session"));
  mpETHSessionMappingMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_eth__session_mapping"));
  mpETHRulesMatchPdrMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_eth__rules_match_pdr"));
  mpETHSessionPdrsMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_eth__session_pdrs"));
}

/*---------------------------------------------------------------------------------------------------------------*/
