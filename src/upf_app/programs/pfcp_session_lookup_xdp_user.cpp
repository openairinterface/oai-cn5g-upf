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
// PFCP_Session_LookupProgram::PFCP_Session_LookupProgram(
//     const std::string& gtpInterface, const std::string& udpInterface,
//     const upf_config& upf_cfg)
//     : mGTPInterface(gtpInterface), mUDPInterface(udpInterface) {
//   struct pfcp_session_lookup_xdp_kernel_c* skel = nullptr;
//   int ret                                       = -1;

//   Logger::upf_app().info("Initializing PFCP Session Lookup BPF program...");
//   // create the open function (callable)
//   auto open_fn = [&upf_cfg, this]() -> pfcp_session_lookup_xdp_kernel_c* {
//     struct pfcp_session_lookup_xdp_kernel_c* skel =
//         pfcp_session_lookup_xdp_kernel_c__open();
//     if (!skel) {
//       Logger::upf_app().error("Failed to open BPF skeleton");
//       return nullptr;
//     }

//     // configure maps / rodata here (same pattern as kernel perf)
//     uint32_t max_rules_match_pdr =
//         upf_cfg.max_pdrs_per_pdu_session * upf_cfg.max_pdu_session;
//     bpf_map__set_max_entries(
//         skel->maps.m_upf_interfaces, upf_cfg.max_upf_interfaces);
//     bpf_map__set_max_entries(
//         skel->maps.m_redirect_interfaces,
//         upf_cfg.max_upf_redirect_interfaces);
//     bpf_map__set_max_entries(
//         skel->maps.m_session_mapping, upf_cfg.max_pdu_session);
//     bpf_map__set_max_entries(
//         skel->maps.m_session_pdrs, upf_cfg.max_pdrs_per_pdu_session);
//     bpf_map__set_max_entries(
//         skel->maps.m_sdf_filter, upf_cfg.max_sdf_filters_per_pdu_session);
//     bpf_map__set_max_entries(skel->maps.m_arp_table,
//     upf_cfg.max_arp_entries);
//     bpf_map__set_max_entries(skel->maps.m_rules_match_pdr,
//     max_rules_match_pdr);

//     redirect interfaces and arp tables sould be less or
//         equal than max upf interfaces(
//             even incuding n4 since URR is also using this interface to
//             forward
//                 traffic to SMF)

//         /*---------------------------------------------------------------------------------------------------------------*/
//         struct {
//       __uint(type, BPF_MAP_TYPE_DEVMAP);
//       __uint(max_entries, MAX_INTERFACES);
//       __type(key, u32);    // id
//       __type(value, u32);  // tx port
//     } m_redirect_interfaces SEC(".maps");

//     /*---------------------------------------------------------------------------------------------------------------*/
//     struct {
//       __uint(type, BPF_MAP_TYPE_HASH);
//       __uint(max_entries, ARP_ENTRIES_MAX_SIZE);
//       __type(key, u32);                     // IPv4 address
//       __type(value, struct s_arp_mapping);  // <IP Address, MAC address>
//     } m_arp_table SEC(".maps");

//     // optionally set rodata fields:
//     if (skel->rodata) {
//       skel->rodata->max_upf_interfaces = upf_cfg.max_upf_interfaces;
//       skel->rodata->max_upf_redirect_interfaces =
//           upf_cfg.max_upf_redirect_interfaces;
//       skel->rodata->max_pdu_session          = upf_cfg.max_pdu_session;
//       skel->rodata->max_pdrs_per_pdu_session =
//       upf_cfg.max_pdrs_per_pdu_session;
//       skel->rodata->max_sdf_filters_per_pdu_session =
//           upf_cfg.max_sdf_filters_per_pdu_session;
//       skel->rodata->max_arp_entries = upf_cfg.max_arp_entries;
//     }

//     return skel;
//   };

//   // now create the lifecycle object with a callable open_fn (not a raw skel)
//   mpLifeCycle = std::make_shared<PFCP_Session_LookupProgramLifeCycle>(
//       open_fn,
//       /* load */ pfcp_session_lookup_xdp_kernel_c__load,
//       /* attach */ pfcp_session_lookup_xdp_kernel_c__attach,
//       /* destroy*/ pfcp_session_lookup_xdp_kernel_c__destroy);
// }

/*---------------------------------------------------------------------------------------------------------------*/

void PFCP_Session_LookupProgram::configure_bpf_maps_and_rodata(
    struct pfcp_session_lookup_xdp_kernel_c* skel, const upf_config& upf_cfg) {
  if (!skel) {
    Logger::upf_app().error("Null skeleton in configure_bpf_maps_and_rodata");
    return;
  }

  // Compute derived limits
  uint32_t max_rules_match_pdr =
      upf_cfg.max_pdrs_per_pdu_session * upf_cfg.max_pdu_session;

  // Configure BPF map sizes
  bpf_map__set_max_entries(
      skel->maps.m_upf_interfaces, upf_cfg.max_upf_interfaces);
  bpf_map__set_max_entries(
      skel->maps.m_redirect_interfaces, upf_cfg.max_upf_redirect_interfaces);
  bpf_map__set_max_entries(
      skel->maps.m_session_mapping, upf_cfg.max_pdu_session);
  bpf_map__set_max_entries(
      skel->maps.m_session_pdrs, upf_cfg.max_pdrs_per_pdu_session);
  bpf_map__set_max_entries(
      skel->maps.m_sdf_filter, upf_cfg.max_sdf_filters_per_pdu_session);
  bpf_map__set_max_entries(skel->maps.m_arp_table, upf_cfg.max_arp_entries);
  bpf_map__set_max_entries(skel->maps.m_rules_match_pdr, max_rules_match_pdr);

  // Configure .rodata constants (if available)
  if (skel->rodata) {
    skel->rodata->max_upf_interfaces = upf_cfg.max_upf_interfaces;
    skel->rodata->max_upf_redirect_interfaces =
        upf_cfg.max_upf_redirect_interfaces;
    skel->rodata->max_pdu_session          = upf_cfg.max_pdu_session;
    skel->rodata->max_pdrs_per_pdu_session = upf_cfg.max_pdrs_per_pdu_session;
    skel->rodata->max_sdf_filters_per_pdu_session =
        upf_cfg.max_sdf_filters_per_pdu_session;
    skel->rodata->max_arp_entries = upf_cfg.max_arp_entries;
  }
}

/*---------------------------------------------------------------------------------------------------------------*/

PFCP_Session_LookupProgram::PFCP_Session_LookupProgram(
    const std::string& gtpInterface, const std::string& udpInterface,
    const upf_config& upf_cfg)
    : mGTPInterface(gtpInterface), mUDPInterface(udpInterface) {
  struct pfcp_session_lookup_xdp_kernel_c* skel = nullptr;
  int ret                                       = -1;

  Logger::upf_app().info("Initializing PFCP Session Lookup BPF program...");

  auto open_fn = [&upf_cfg, this]() -> pfcp_session_lookup_xdp_kernel_c* {
    struct pfcp_session_lookup_xdp_kernel_c* skel =
        pfcp_session_lookup_xdp_kernel_c__open();
    if (!skel) {
      Logger::upf_app().error("Failed to open BPF skeleton");
      return nullptr;
    }

    // Configure maps and rodata
    this->configure_bpf_maps_and_rodata(skel, upf_cfg);
    return skel;
  };

  mpLifeCycle = std::make_shared<PFCP_Session_LookupProgramLifeCycle>(
      open_fn,
      /* load */ pfcp_session_lookup_xdp_kernel_c__load,
      /* attach */ pfcp_session_lookup_xdp_kernel_c__attach,
      /* destroy*/ pfcp_session_lookup_xdp_kernel_c__destroy);
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
        "QoS enforcement is enabled in the configuration. A TC BPF section "
        "is "
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

/*---------------------------------------------------------------------------------------------------------------*/
void PFCP_Session_LookupProgram::setFramedRouting(bool enable) {
  uint8_t value = (enable) ? 1 : 0;
  uint8_t key   = 0;
  mpFramedRouteFlagMap->update(key, value, BPF_ANY);
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
}

/*---------------------------------------------------------------------------------------------------------------*/
