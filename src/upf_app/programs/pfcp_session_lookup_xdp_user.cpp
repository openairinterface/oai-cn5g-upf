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
  // Open the eBPF skeleton
  // auto skel = pfcp_session_lookup_xdp_kernel_c__open();
  // if (!skel) {
  //   std::cerr << "Failed to open eBPF skeleton" << std::endl;
  //   return;
  // }
  // // Resize the map BEFORE loading
  // struct bpf_map* arp_table_map =
  //     bpf_object__find_map_by_name(skel->obj, "m_arp_table");
  // if (!arp_table_map) {
  //   std::cerr << "Failed to find map: m_arp_table" << std::endl;
  // } else {
  //   int max_entries = 55;  // Set your new desired size
  //   if (bpf_map__set_max_entries(arp_table_map, max_entries)) {
  //     std::cerr << "Failed to resize map: m_arp_table" << std::endl;
  //   }
  // }

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
  mpLifeCycle->tearDown();
}

/*---------------------------------------------------------------------------------------------------------------*/
void PFCP_Session_LookupProgram::updateProgramMap(uint32_t key, uint32_t fd) {
  mpTeidSessionMap->update(key, fd, BPF_ANY);
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
std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getTeidSessionMap() const {
  return mpTeidSessionMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getUeIpSessionMap() const {
  return mpUeIpSessionMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getNextProgRuleMap() const {
  return mpNextProgRuleMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getNextProgRuleIndexMap()
    const {
  return mpNextProgRuleIndexMap;
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

std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getSessionPdrsMap() const {
  return mpSessionPdrsMap;
}

std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getSdfFilterMap() const {
  return mpSdfFilterMap;
}

std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getQosEnablingMap() const {
  return mpQosEnablingMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
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
}

/*---------------------------------------------------------------------------------------------------------------*/
