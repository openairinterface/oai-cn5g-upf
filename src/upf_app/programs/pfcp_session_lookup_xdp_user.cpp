/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */
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
#include "utils/net_utils.hpp"
#include "utils/bpf_utils.hpp"

using namespace oai::config;
extern upf_config upf_cfg;

using namespace oai::utils::net;
using namespace oai::utils::bpf;

class XDPSection {
 public:
  static constexpr const char* Uplink   = "xdp_handle_uplink";
  static constexpr const char* Downlink = "xdp_handle_downlink";
  static constexpr const char* Shaping  = "xdp_handle_shaping";
};

/*---------------------------------------------------------------------------------------------------------------*/
void PFCP_Session_LookupProgram::configurePfcpSessionLookupMaps(
    struct pfcp_session_lookup_xdp_kernel_c* skel, const upf_config& upf_cfg) {
  if (!skel) {
    Logger::upf_app().error("Null skeleton in configurePfcpSessionLookupMaps");
    return;
  }

  int num_ifaces = count_available_interfaces();
  if (upf_cfg.max_upf_interfaces > num_ifaces) {
    Logger::upf_app().warn(
        "Configured max_upf_interfaces (%u) exceeds available system "
        "interfaces (%d). "
        "Clamping to %d.",
        upf_cfg.max_upf_interfaces, num_ifaces, num_ifaces);
  }

  if (upf_cfg.max_upf_redirect_interfaces > upf_cfg.max_upf_interfaces) {
    Logger::upf_app().error(
        "Invalid config: max_upf_redirect_interfaces (%u) cannot exceed "
        "max_upf_interfaces (%u).",
        upf_cfg.max_upf_redirect_interfaces, upf_cfg.max_upf_interfaces);
    throw std::runtime_error(
        "Invalid UPF configuration (redirect > interfaces)");
  }

  if (upf_cfg.max_upf_redirect_interfaces > upf_cfg.max_arp_entries) {
    Logger::upf_app().warn(
        "max_upf_redirect_interfaces (%u) > max_arp_entries (%u): "
        "redirects may not all resolve via ARP.",
        upf_cfg.max_upf_redirect_interfaces, upf_cfg.max_arp_entries);
  }

  // Compute derived limits
  uint32_t max_rules_match_pdr =
      upf_cfg.max_pdrs_per_pdu_session * upf_cfg.max_pdu_session;

  uint32_t max_qos_enabling = upf_cfg.max_pdu_session;

  bool ok = true;
  ok &= configure_map_max_entries(
      skel->maps.m_upf_interfaces, "m_upf_interfaces",
      upf_cfg.max_upf_interfaces);
  ok &= configure_map_max_entries(
      skel->maps.m_redirect_interfaces, "m_redirect_interfaces",
      upf_cfg.max_upf_redirect_interfaces);
  ok &= configure_map_max_entries(
      skel->maps.m_session_mapping, "m_session_mapping",
      upf_cfg.max_pdu_session);
  ok &= configure_map_max_entries(
      skel->maps.m_session_pdrs, "m_session_pdrs",
      upf_cfg.max_pdrs_per_pdu_session);
  ok &= configure_map_max_entries(
      skel->maps.m_sdf_filter, "m_sdf_filter",
      upf_cfg.max_sdf_filters_per_pdu_session);
  ok &= configure_map_max_entries(
      skel->maps.m_arp_table, "m_arp_table", upf_cfg.max_arp_entries);
  ok &= configure_map_max_entries(
      skel->maps.m_rules_match_pdr, "m_rules_match_pdr", max_rules_match_pdr);
  ok &= configure_map_max_entries(
      skel->maps.m_qos_enabling, "m_qos_enabling", max_qos_enabling);
  if (!ok) {
    Logger::upf_app().error(
        "One or more BPF map configurations failed for PFCP Session Lookup "
        "program.");
    throw std::runtime_error("PFCP Session Lookup map configuration failed");
  }

  // Configure .rodata constants (if available)
  if (skel->rodata) {
    skel->rodata->max_upf_interfaces = upf_cfg.max_upf_interfaces;
    skel->rodata->max_upf_redirect_interfaces =
        upf_cfg.max_upf_redirect_interfaces;
    skel->rodata->max_pdu_session          = upf_cfg.max_pdu_session;
    skel->rodata->max_pdrs_per_pdu_session = upf_cfg.max_pdrs_per_pdu_session;
    skel->rodata->max_sdf_filters_per_pdu_session =
        upf_cfg.max_sdf_filters_per_pdu_session;
    skel->rodata->max_arp_entries  = upf_cfg.max_arp_entries;
    skel->rodata->max_qos_enabling = upf_cfg.max_pdu_session;

    // Configure PDR lookup behavior
    skel->rodata->config.ignore_qfi_for_uplink = upf_cfg.ignore_qfi_for_uplink;

    Logger::upf_app().info(
        "PDR Lookup Config: ignore_qfi_for_uplink=%s",
        upf_cfg.ignore_qfi_for_uplink ? "true" : "false");
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
    this->configurePfcpSessionLookupMaps(skel, upf_cfg);
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

  const std::string udpIface =
      UserPlaneComponent::getInstance().getUDPInterface();
  const std::string gtpIface =
      UserPlaneComponent::getInstance().getGTPInterface();

  uint32_t udpInterfaceIndex = if_nametoindex(udpIface.c_str());
  uint32_t gtpInterfaceIndex = if_nametoindex(gtpIface.c_str());
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

/*---------------------------------------------------------------------------------------------------------------*/
void PFCP_Session_LookupProgram::setFramedRouting(bool enable) {
  uint8_t value = (enable) ? 1 : 0;
  uint8_t key   = 0;
  mpFramedRouteFlagMap->update(key, value, BPF_ANY);
}

// ---------------------------------------------------------------------------------------------------------------*/
// For ETH PDU session
std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getETHMacPduSessionMap()
    const {
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
