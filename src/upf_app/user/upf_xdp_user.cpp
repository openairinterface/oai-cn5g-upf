/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

/**
 * @file upf_xdp_user.cpp
 * @brief Implementation of XDP program management
 * @author OpenAirInterface
 * @date 2025
 */

#include "upf_xdp_user.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdexcept>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "interfaces.h"
#include "logger.hpp"
#include "upf_config.hpp"
#include "utils/net_utils.hpp"
#include "utils/bpf_utils.hpp"
#include "upf_xdp_limits.h"
#include "UserPlaneComponent.h"
#include "sdf_filter.h"

using namespace oai::config;
using namespace oai::utils::net;
using namespace oai::utils::bpf;

extern upf_config upf_cfg;

/**
 * @brief XDP section names for different packet paths
 */
class XDPSection {
 public:
  static constexpr const char* Uplink = "xdp_uplink";  ///< GTP-U uplink
  static constexpr const char* Downlink =
      "xdp_downlink";                                ///< Standard downlink
  static constexpr const char* Shaping = "xdp_qos";  ///< QoS enforcement
};

//------------------------------------------------------------------------------
void UPF_XDPProgram::ConfigurePfcpSessionLookupMaps(
    struct upf_xdp_kern_c* skel, const upf_config& upf_cfg) {
  if (!skel) {
    Logger::upf_app().error("Null skeleton in ConfigurePfcpSessionLookupMaps");
    return;
  }

  // Validate configuration against system limits
  int num_ifaces = CountAvailableInterfaces();
  if (upf_cfg.max_upf_interfaces > static_cast<uint32_t>(num_ifaces)) {
    Logger::upf_app().warn(
        "Configured max_upf_interfaces (%u) exceeds available system "
        "interfaces (%d). Clamping to %d.",
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

  if (upf_cfg.max_pdrs_per_pdu_session > MAX_PDRS_PER_PDU_SESSION_LIMIT) {
    Logger::upf_app().error(
        "Configuration error: max_pdrs_per_pdu_session (%u) exceeds "
        "compile-time limit (%u). Please recompile with a larger "
        "MAX_PDRS_PER_PDU_SESSION_LIMIT or reduce your configuration.",
        upf_cfg.max_pdrs_per_pdu_session, MAX_PDRS_PER_PDU_SESSION_LIMIT);
    throw std::runtime_error(
        "max_pdrs_per_pdu_session exceeds compile-time limit");
  }

  // Compute derived limits
  uint32_t max_rules_match_pdr =
      upf_cfg.max_pdrs_per_pdu_session * upf_cfg.max_pdu_sessions;

  uint32_t max_qos_enabling = upf_cfg.max_pdu_sessions;

  // Configure all map sizes
  bool ok = true;
  ok &= ConfigureMapMaxEntries(
      skel->maps.upf_interface_map, "upf_interface_map",
      upf_cfg.max_upf_interfaces);
  ok &= ConfigureMapMaxEntries(
      skel->maps.redirect_interfaces_map, "redirect_interfaces_map",
      upf_cfg.max_upf_redirect_interfaces);
  ok &= ConfigureMapMaxEntries(
      skel->maps.session_by_ue_ip_map, "session_by_ue_ip_map",
      upf_cfg.max_pdu_sessions);
  ok &= ConfigureMapMaxEntries(
      skel->maps.pdrs_per_session_map, "pdrs_per_session_map",
      upf_cfg.max_pdrs_per_pdu_session);
  ok &= ConfigureMapMaxEntries(
      skel->maps.sdf_filters_map, "sdf_filters_map",
      upf_cfg.max_sdf_filters_per_pdu_session);
  ok &= ConfigureMapMaxEntries(
      skel->maps.arp_table_map, "arp_table_map", upf_cfg.max_arp_entries);
  ok &= ConfigureMapMaxEntries(
      skel->maps.rules_match_pdr_map, "rules_match_pdr_map",
      max_rules_match_pdr);
  ok &= ConfigureMapMaxEntries(
      skel->maps.session_qos_enabled_map, "session_qos_enabled_map",
      max_qos_enabling);

  if (!ok) {
    Logger::upf_app().error(
        "One or more BPF map configurations failed for PFCP Session Lookup "
        "program.");
    throw std::runtime_error("PFCP Session Lookup map configuration failed");
  }

  // Configure .rodata constants (if available)
  if (skel->rodata) {
    skel->rodata->MAX_UPF_INTERFACES = upf_cfg.max_upf_interfaces;
    skel->rodata->MAX_UPF_REDIRECT_INTERFACES =
        upf_cfg.max_upf_redirect_interfaces;
    skel->rodata->MAX_PDU_SESSIONS         = upf_cfg.max_pdu_sessions;
    skel->rodata->MAX_PDRS_PER_PDU_SESSION = upf_cfg.max_pdrs_per_pdu_session;
    skel->rodata->MAX_SDF_FILTERS_PER_PDU_SESSION =
        upf_cfg.max_sdf_filters_per_pdu_session;
    skel->rodata->MAX_ARP_ENTRIES  = upf_cfg.max_arp_entries;
    skel->rodata->MAX_QOS_ENABLING = upf_cfg.max_pdu_sessions;
  }
}

//------------------------------------------------------------------------------
UPF_XDPProgram::UPF_XDPProgram(
    const std::string& gtp_interface, const std::string& udp_interface,
    const upf_config& upf_cfg)
    : BPFProgram(),
      gtp_interface_(gtp_interface),
      udp_interface_(udp_interface) {
  Logger::upf_app().info("Initializing UPF XDP Program...");

  // Define the 'open' lambda for the XDP skeleton
  auto open_fn = [&upf_cfg, this]() -> upf_xdp_kern_c* {
    struct upf_xdp_kern_c* skel = upf_xdp_kern_c__open();
    if (!skel) {
      Logger::upf_app().error("Failed to open BPF skeleton");
      return nullptr;
    }

    // Configure maps and rodata
    this->ConfigurePfcpSessionLookupMaps(skel, upf_cfg);
    return skel;
  };

  // Initialize lifecycle management
  lifecycle_ = std::make_shared<UPF_XDPProgramLifeCycle>(
      open_fn,
      /* load */ upf_xdp_kern_c__load,
      /* attach */ upf_xdp_kern_c__attach,
      /* destroy */ upf_xdp_kern_c__destroy);
}

//------------------------------------------------------------------------------
void UPF_XDPProgram::CreateUpfInterfaceMapEntry(reference_point_t s) {
  struct interface_config iface;
  __builtin_memset(&iface, 0, sizeof(interface_config));

  switch (s) {
    case N3_INTERFACE:
      iface.ipv4_address = upf_cfg.n3.addr4.s_addr;
      iface.port         = upf_cfg.n3.port;
      iface.if_name      = upf_cfg.n3.if_name.c_str();
      GetIfaceMap()->Update(s, iface, BPF_ANY);
      break;

    case N6_INTERFACE:
      iface.ipv4_address = upf_cfg.n6.addr4.s_addr;
      iface.port         = upf_cfg.n6.port;
      iface.if_name      = upf_cfg.n6.if_name.c_str();
      GetIfaceMap()->Update(s, iface, BPF_ANY);
      break;

    case N4_INTERFACE:
      iface.ipv4_address = upf_cfg.n4.addr4.s_addr;
      iface.port         = upf_cfg.n4.port;
      iface.if_name      = upf_cfg.n4.if_name.c_str();
      GetIfaceMap()->Update(s, iface, BPF_ANY);
      break;

    case N9_INTERFACE:
      Logger::upf_app().error("Reference Point N9 not defined");
      break;

    case N19_INTERFACE:
      Logger::upf_app().error("Reference Point N19 not defined");
      break;

    default:
      Logger::upf_app().error("The Reference Point is not defined");
  }
}

//------------------------------------------------------------------------------
UPF_XDPProgram::~UPF_XDPProgram() {}

//------------------------------------------------------------------------------
void UPF_XDPProgram::Setup(bool is_qos_enabled) {
  skeleton_ = lifecycle_->open();
  InitializeMaps();
  lifecycle_->load();
  lifecycle_->attach();

  const std::string udp_iface =
      UserPlaneComponent::GetInstance().GetUDPInterface();
  const std::string gtp_iface =
      UserPlaneComponent::GetInstance().GetGTPInterface();

  uint32_t udp_interface_index = if_nametoindex(udp_iface.c_str());
  uint32_t gtp_interface_index = if_nametoindex(gtp_iface.c_str());
  uint32_t uplink_id           = static_cast<uint32_t>(FlowDirection::UPLINK);
  uint32_t downlink_id         = static_cast<uint32_t>(FlowDirection::DOWNLINK);

  egress_interface_map_->Update(uplink_id, udp_interface_index, BPF_ANY);
  egress_interface_map_->Update(downlink_id, gtp_interface_index, BPF_ANY);

  Logger::upf_app().info(
      "Reference points configured: N3 (%s), N4 (%s), N6 (%s)",
      upf_cfg.n3.if_name.c_str(), upf_cfg.n4.if_name.c_str(),
      upf_cfg.n6.if_name.c_str());
  CreateUpfInterfaceMapEntry(N3_INTERFACE);
  CreateUpfInterfaceMapEntry(N6_INTERFACE);
  CreateUpfInterfaceMapEntry(N4_INTERFACE);

  // Validate interface names
  if (udp_interface_.empty() || gtp_interface_.empty()) {
    Logger::upf_app().error("GTP or UDP interface not defined!");
    throw std::runtime_error("GTP or UDP interface not defined!");
  }

  Logger::upf_app().debug(
      "Link GTP XDP Section to interface %s", gtp_interface_.c_str());
  lifecycle_->link(XDPSection::Uplink, gtp_interface_.c_str());

  Logger::upf_app().debug(
      "Link Non-GTP XDP Section to interface %s", udp_interface_.c_str());
  if (is_qos_enabled) {
    Logger::upf_app().debug(
        "QoS enforcement is enabled - attaching TC BPF section");
    lifecycle_->link(XDPSection::Shaping, udp_interface_.c_str());
  } else {
    Logger::upf_app().debug("QoS enforcement: disabled");
    lifecycle_->link(XDPSection::Downlink, udp_interface_.c_str());
  }
}

//------------------------------------------------------------------------------
void UPF_XDPProgram::TearDown() {
  lifecycle_->tearDown();
}

//------------------------------------------------------------------------------
void UPF_XDPProgram::RemoveProgramMap(uint32_t key) {
  int32_t fd;
  // Remove only if exists
  if (teid_session_map_->Lookup(key, &fd) == 0) {
    teid_session_map_->Remove(key);
  }
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMaps> UPF_XDPProgram::GetMaps() {
  return maps_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> UPF_XDPProgram::GetMapByName(
    const std::string& map_name) {
  // Map name aliases to actual map members
  // Support both new names and legacy names for compatibility

  if (map_name == "session_map" || map_name == "session_by_ue_ip_map") {
    return session_mapping_map_;
  }

  if (map_name == "arp_table" || map_name == "arp_table_map") {
    return arp_table_map_;
  }

  if (map_name == "redirect_interfaces_map") {
    return egress_interface_map_;
  }

  if (map_name == "upf_interface_map") {
    return upf_iface_map_;
  }

  if (map_name == "pdrs_per_session_map") {
    return session_pdrs_map_;
  }

  if (map_name == "rules_match_pdr_map") {
    return rules_match_pdr_map_;
  }

  if (map_name == "sdf_filters_map") {
    return sdf_filter_map_;
  }

  if (map_name == "session_qos_enabled_map") {
    return qos_enabling_map_;
  }

  if (map_name == "m_framed_route_mapping") {
    return framed_route_mapping_map_;
  }

  if (map_name == "framed_routing_flag") {
    return framed_route_flag_map_;
  }

  // Map not found
  Logger::upf_app().warn("Map '%s' not found in XDP program", map_name.c_str());
  return nullptr;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> UPF_XDPProgram::GetSessionMappingMap() const {
  return session_mapping_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> UPF_XDPProgram::GetEgressInterfaceMap() const {
  return egress_interface_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> UPF_XDPProgram::GetArpTableMap() const {
  return arp_table_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> UPF_XDPProgram::GetIfaceMap() const {
  return upf_iface_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> UPF_XDPProgram::GetRulesMatchPdrMap() const {
  return rules_match_pdr_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> UPF_XDPProgram::GetSessionPdrsMap() const {
  return session_pdrs_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> UPF_XDPProgram::GetSdfFilterMap() const {
  return sdf_filter_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> UPF_XDPProgram::GetQosEnablingMap() const {
  return qos_enabling_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> UPF_XDPProgram::GetFramedRouteMappingMap() {
  return framed_route_mapping_map_;
}

//------------------------------------------------------------------------------
void UPF_XDPProgram::UpdateFramedRouteMappingMap(
    uint32_t ue_ip, FramedRoutingKeyBPF key) {
  uint32_t hash_key = hash_framed_routing_key(&key);
  Logger::upf_app().debug(
      "Update framed routing map with key: %u, value: %pI4", hash_key, ue_ip);
  framed_route_mapping_map_->Update(hash_key, ue_ip, BPF_ANY);
}

//------------------------------------------------------------------------------
void UPF_XDPProgram::RemoveFramedRoute(FramedRoutingKeyBPF key) {
  uint32_t hash_key = hash_framed_routing_key(&key);
  uint32_t ue_ip;
  if (framed_route_mapping_map_->Lookup(hash_key, &ue_ip) == 0) {
    framed_route_mapping_map_->Remove(hash_key);
  }
}

//------------------------------------------------------------------------------
void UPF_XDPProgram::SetFramedRouting(bool enable) {
  uint8_t value = enable ? 1 : 0;
  uint8_t key   = 0;
  framed_route_flag_map_->Update(key, value, BPF_ANY);
}

//------------------------------------------------------------------------------
void UPF_XDPProgram::InitializeMaps() {
  // Store all maps available in the program
  maps_ = std::make_shared<BPFMaps>(lifecycle_->getBPFSkeleton()->skeleton);

  session_mapping_map_ =
      std::make_shared<BPFMap>(maps_->GetMap("session_by_ue_ip_map"));
  arp_table_map_ = std::make_shared<BPFMap>(maps_->GetMap("arp_table_map"));
  egress_interface_map_ =
      std::make_shared<BPFMap>(maps_->GetMap("redirect_interfaces_map"));
  upf_iface_map_ = std::make_shared<BPFMap>(maps_->GetMap("upf_interface_map"));
  session_pdrs_map_ =
      std::make_shared<BPFMap>(maps_->GetMap("pdrs_per_session_map"));
  rules_match_pdr_map_ =
      std::make_shared<BPFMap>(maps_->GetMap("rules_match_pdr_map"));
  sdf_filter_map_ = std::make_shared<BPFMap>(maps_->GetMap("sdf_filters_map"));
  qos_enabling_map_ =
      std::make_shared<BPFMap>(maps_->GetMap("session_qos_enabled_map"));
  framed_route_mapping_map_ =
      std::make_shared<BPFMap>(maps_->GetMap("m_framed_route_mapping"));
  framed_route_flag_map_ =
      std::make_shared<BPFMap>(maps_->GetMap("framed_routing_flag"));
}

//------------------------------------------------------------------------------
size_t UPF_XDPProgram::GetMapCount() const {
  if (!maps_) {
    return 0;
  }
  return maps_->GetMapCount();
}

//------------------------------------------------------------------------------
bool UPF_XDPProgram::IsNativeXdp(const std::string& interface) const {
  if (!lifecycle_) {
    return false;
  }
  return lifecycle_->IsNativeXdp(interface);
}

//------------------------------------------------------------------------------
std::string UPF_XDPProgram::GetXdpModeString(
    const std::string& interface) const {
  if (!lifecycle_) {
    return "Unknown";
  }
  return lifecycle_->GetXdpModeString(interface);
}