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

// clang-format off
/* Modified by: Franck Messaoudi <franck.messaoudi@eurecom.fr>
 * Date:        2026-03
 * Changes:     Boy Scout cleanup — changelogs, §-refs, separator lines.
 *              V17.10.0 harmonisation:
 *                - [BUG FIX] InitializeMaps(): urr_config_map_, urr_volume_map_,
 *                  bar_config_map_, bar_state_map_, mar_rules_map_,
 *                  feature_dispatch_map_, session_mac_map_ were declared as
 *                  member variables but never assigned — all remained nullptr.
 *                  SessionPrograms::CleanupBpfMapEntries() and
 *                  URRProgram/BARProgram/MARProgram therefore received nullptr
 *                  map references and silently discarded all cleanup calls.
 *                  Fixed: all seven maps now initialised from the skeleton.
 *                - [BUG FIX] GetMapByName(): missing cases for urr_config_map,
 *                  urr_volume_map, bar_config_map, bar_state_map, mar_rules_map,
 *                  feature_dispatch_map, session_by_mac_map — all returned
 *                  nullptr. Added cases for every map advertised in the
 *                  docstring.
 *                - [BUG FIX] GetMapByName(): "session_rules_enabled_map" not
 *                  handled; SessionPrograms.cpp uses this name (the BPF map was
 *                  renamed from session_qos_enabled_map during the
 *                  rules-enabled-flags refactor). Added as alias for
 *                  qos_enabling_map_.
 *                - [BUG FIX] CreateUpfInterfaceMapEntry(): was reading directly
 *                  from upf_cfg.n3/n4/n6 — inconsistent with the rest of the
 *                  codebase which reads from upf::g_net_cfg after
 *                  BuildNetworkConfig(). Fixed to use upf::Get*() getters.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 *              3GPP TS 23.501          (Release 17)           — 5G System Arch.
 */
// clang-format on

/**
 * @file upf_xdp_user.cpp
 * @brief Implementation of XDP program management
 * @author OpenAirInterface, Franck Messaoudi
 * @date 2025 / 2026-03
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
    struct upf_xdp_kern_c* skel) {
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

  /* Compute Map Sizes:
   * Two types of maps:
   *	1. SESSION-SCOPED: size = max_pdu_sessions
   *	2. GLOBAL/RULE:    size = max_pdu_sessions × per_session_limit
   */

  // Session-scoped maps: one entry per session
  uint32_t max_sessions = upf_cfg.max_pdu_sessions;

  // Global maps: entries across ALL sessions
  // Total PDR-FAR-QER associations = sessions × PDRs_per_session
  uint32_t total_pdr_rules = max_sessions * upf_cfg.max_pdrs_per_pdu_session;

  // Total SDF filters = sessions × SDF_filters_per_session
  uint32_t total_sdf_filters =
      max_sessions * upf_cfg.max_sdf_filters_per_pdu_session;

  // // Compute derived limits
  // uint32_t max_rules_match_pdr =
  //     upf_cfg.max_pdrs_per_pdu_session * upf_cfg.max_pdu_sessions;

  // uint32_t max_qos_enabling = upf_cfg.max_pdu_sessions;

  /**
   * Configure All Map Sizes:
   */

  bool ok = true;

  // --- INTERFACE MAPS (fixed size) ---
  ok &= ConfigureMapMaxEntries(
      skel->maps.upf_interface_map, "upf_interface_map",
      upf_cfg.max_upf_interfaces);

  ok &= ConfigureMapMaxEntries(
      skel->maps.redirect_interfaces_map, "redirect_interfaces_map",
      upf_cfg.max_upf_redirect_interfaces);

  // --- SESSION-SCOPED MAPS (size = max_sessions) ---
  ok &= ConfigureMapMaxEntries(
      skel->maps.session_by_ue_ip_map, "session_by_ue_ip_map", max_sessions);

  // pdrs_per_session_map: ONE entry per session (value is array of PDRs)
  // Size = max_sessions, NOT max_pdrs_per_pdu_session!
  ok &= ConfigureMapMaxEntries(
      skel->maps.pdrs_per_session_map, "pdrs_per_session_map",
      max_sessions); /*max_pdrs_per_pdu_session*/

  ok &= ConfigureMapMaxEntries(
      skel->maps.session_qos_enabled_map, "session_qos_enabled_map",
      max_sessions);

  ok &= ConfigureMapMaxEntries(
      skel->maps.m_framed_route_mapping, "m_framed_route_mapping",
      max_sessions);

  // --- GLOBAL RULE MAPS (size = sessions × per_session_limit) ---

  // rules_match_pdr_map: PDR rule associations across ALL sessions
  // Size = max_sessions × max_pdrs_per_session
  ok &= ConfigureMapMaxEntries(
      skel->maps.rules_match_pdr_map, "rules_match_pdr_map", total_pdr_rules);

  // sdf_filters_map: SDF filters across ALL sessions
  // Size = max_sessions × max_sdf_filters_per_session
  // CRITICAL: Do NOT use max_sdf_filters_per_pdu_session (that's per-session!)
  ok &= ConfigureMapMaxEntries(
      skel->maps.sdf_filters_map, "sdf_filters_map", total_sdf_filters);

  // --- NETWORK MAPS ---
  ok &= ConfigureMapMaxEntries(
      skel->maps.arp_table_map, "arp_table_map", upf_cfg.max_arp_entries);

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
    const std::string& gtp_interface, const std::string& non_gtp_interface)
    : BPFProgram(),
      gtp_interface_(gtp_interface),
      non_gtp_interface_(non_gtp_interface) {
  Logger::upf_app().info("Initializing UPF XDP Program...");

  // Define the 'open' lambda for the XDP skeleton
  auto open_fn = [this]() -> upf_xdp_kern_c* {
    struct upf_xdp_kern_c* skel = upf_xdp_kern_c__open();
    if (!skel) {
      Logger::upf_app().error("Failed to open BPF skeleton");
      return nullptr;
    }

    // Configure maps and rodata
    this->ConfigurePfcpSessionLookupMaps(skel);
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

  // Read from upf::g_net_cfg — populated by Configuration::BuildNetworkConfig()
  // before Setup() is called.  Do NOT read from upf_cfg directly here.
  switch (s) {
    case N3_INTERFACE:
      iface.ipv4_address = upf::GetN3Ip();
      iface.port         = upf::GetN3Port();
      iface.if_name      = upf::GetN3Iface().c_str();
      GetIfaceMap()->Update(s, iface, BPF_ANY);
      break;

    case N6_INTERFACE:
      iface.ipv4_address = upf::GetN6Ip();
      // N6 port not yet exposed by YAML parser; use 0 until added.
      iface.port    = 0;
      iface.if_name = upf::GetN6Iface().c_str();
      GetIfaceMap()->Update(s, iface, BPF_ANY);
      break;

    case N4_INTERFACE:
      iface.ipv4_address = upf::GetN4Ip();
      iface.port         = upf::GetN4Port();
      iface.if_name      = upf::GetN4Iface().c_str();
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
void UPF_XDPProgram::Setup(const PipelineFeatureFlags& flags) {
  skeleton_ = lifecycle_->open();
  InitializeMaps();
  lifecycle_->load();
  lifecycle_->attach();

  const std::string non_gtp_iface =
      UserPlaneComponent::GetInstance().GetNonGTPInterface();
  const std::string gtp_iface =
      UserPlaneComponent::GetInstance().GetGTPInterface();

  uint32_t non_gtp_interface_index = if_nametoindex(non_gtp_iface.c_str());
  uint32_t gtp_interface_index     = if_nametoindex(gtp_iface.c_str());

  uint32_t uplink_id   = static_cast<uint32_t>(FlowDirection::UPLINK);
  uint32_t downlink_id = static_cast<uint32_t>(FlowDirection::DOWNLINK);

  egress_interface_map_->Update(uplink_id, non_gtp_interface_index, BPF_ANY);
  egress_interface_map_->Update(downlink_id, gtp_interface_index, BPF_ANY);

  Logger::upf_app().info(
      "Reference points configured: N3 (%s), N4 (%s), N6 (%s)",
      upf::GetN3Iface().c_str(), upf::GetN4Iface().c_str(),
      upf::GetN6Iface().c_str());
  CreateUpfInterfaceMapEntry(N3_INTERFACE);
  CreateUpfInterfaceMapEntry(N6_INTERFACE);
  CreateUpfInterfaceMapEntry(N4_INTERFACE);

  // Validate interface names
  if (non_gtp_interface_.empty() || gtp_interface_.empty()) {
    Logger::upf_app().error("GTP or UDP interface not defined!");
    throw std::runtime_error("GTP or UDP interface not defined!");
  }

  Logger::upf_app().debug(
      "Link GTP XDP Section to interface %s", gtp_interface_.c_str());
  lifecycle_->link(XDPSection::Uplink, gtp_interface_.c_str());

  Logger::upf_app().debug(
      "Link Non-GTP XDP Section to interface %s", non_gtp_interface_.c_str());
  if (flags.enable_qos) {
    Logger::upf_app().debug(
        "QoS enforcement is enabled - attaching TC BPF section");
    lifecycle_->link(XDPSection::Shaping, non_gtp_interface_.c_str());
  } else {
    Logger::upf_app().debug("QoS enforcement: disabled");
    lifecycle_->link(XDPSection::Downlink, non_gtp_interface_.c_str());
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
  // Map name aliases to actual map members.
  // Supports both canonical names and legacy aliases for backward compat.

  if (map_name == "session_map" || map_name == "session_by_ue_ip_map") {
    return session_mapping_map_;
  }

  if (map_name == "session_by_mac_map") {
    return session_mac_map_;
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

  // "session_rules_enabled_map" is the name used by SessionPrograms.cpp
  // (rules-enabled-flags refactor renamed from session_qos_enabled_map).
  if (map_name == "session_qos_enabled_map" ||
      map_name == "session_rules_enabled_map") {
    return qos_enabling_map_;
  }

  if (map_name == "m_framed_route_mapping") {
    return framed_route_mapping_map_;
  }

  if (map_name == "framed_routing_flag") {
    return framed_route_flag_map_;
  }

  if (map_name == "feature_dispatch_map") {
    return feature_dispatch_map_;
  }

  // URR maps — required by URRProgram and SessionPrograms::CleanupBpfMapEntries
  if (map_name == "urr_config_map") {
    return urr_config_map_;
  }

  if (map_name == "urr_volume_map") {
    return urr_volume_map_;
  }

  // BAR maps — required by BARProgram and SessionPrograms::CleanupBpfMapEntries
  if (map_name == "bar_config_map") {
    return bar_config_map_;
  }

  if (map_name == "bar_state_map") {
    return bar_state_map_;
  }

  // MAR maps — required by MARProgram and SessionPrograms::CleanupBpfMapEntries
  if (map_name == "mar_rules_map") {
    return mar_rules_map_;
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
  session_mac_map_ =
      std::make_shared<BPFMap>(maps_->GetMap("session_by_mac_map"));
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
  feature_dispatch_map_ =
      std::make_shared<BPFMap>(maps_->GetMap("feature_dispatch_map"));

  // URR maps — required by URRProgram (SessionProgramManager)
  urr_config_map_ = std::make_shared<BPFMap>(maps_->GetMap("urr_config_map"));
  urr_volume_map_ = std::make_shared<BPFMap>(maps_->GetMap("urr_volume_map"));

  // BAR maps — required by BARProgram
  bar_config_map_ = std::make_shared<BPFMap>(maps_->GetMap("bar_config_map"));
  bar_state_map_  = std::make_shared<BPFMap>(maps_->GetMap("bar_state_map"));

  // MAR maps — required by MARProgram
  mar_rules_map_ = std::make_shared<BPFMap>(maps_->GetMap("mar_rules_map"));
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
