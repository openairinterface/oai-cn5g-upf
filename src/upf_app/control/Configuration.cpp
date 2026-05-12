/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "Configuration.h"

#include <string>

#include "logger.hpp"
#include "upf_config.hpp"  // upf_config — intentionally local to this TU
#include "upf_network_config.h"  // upf::NetworkConfig, upf::g_net_cfg

using namespace oai::config;

extern upf_config upf_cfg;

// =============================================================================
// upf::g_net_cfg — definition (declared extern in upf_network_config.h)
// Populated at runtime by BuildNetworkConfig() — not at static-init time.
// =============================================================================

namespace upf {
NetworkConfig
    g_net_cfg;  ///< Zero-initialised; populated by BuildNetworkConfig()
}  // namespace upf

// =============================================================================
// Configuration static members
// Initialised to empty string — real values come from upf_cfg in the
// constructor (upf_cfg is fully loaded by then) or from argv overrides.
// Direct file-scope initialisation from upf_cfg was an initialisation-order
// hazard: upf_cfg lives in another TU with no guaranteed init order.
// =============================================================================

std::string Configuration::gtp_interface_              = "";
std::string Configuration::non_gtp_interface_          = "";
unsigned char Configuration::is_socket_buffer_enabled_ = 0;

// =============================================================================
// Constructor — apply argv overrides; read upf_cfg defaults otherwise
// =============================================================================

Configuration::Configuration(int argc, char** argv) {
  // Default from YAML-parsed upf_cfg (safe here — upf_cfg is fully loaded
  // before Configuration is constructed in main()).
  gtp_interface_     = upf_cfg.n3.if_name;
  non_gtp_interface_ = upf_cfg.n6.if_name;

  // argv[1] = N3 (GTP-U) interface, argv[2] = N6 (Data Network) interface.
  // Guard requires argc >= 3 so both argv[1] and argv[2] are valid.
  if (argc >= 3) {
    gtp_interface_     = argv[1];
    non_gtp_interface_ = argv[2];
  }

  Logger::upf_app().info(
      "CLI override: N3 = %s N6 = %s", gtp_interface_.c_str(),
      non_gtp_interface_.c_str());

  for (int i = 1; i < argc; ++i) {
    Logger::upf_app().debug("arg[%d] = %s", i, argv[i]);
  }
}

// =============================================================================
// BuildNetworkConfig — single write-point: upf_cfg → upf::g_net_cfg
// =============================================================================

void Configuration::BuildNetworkConfig() {
  // --- Interface names ---
  upf::g_net_cfg.n3_iface = upf_cfg.n3.if_name;
  upf::g_net_cfg.n6_iface = upf_cfg.n6.if_name;
  upf::g_net_cfg.n4_iface = upf_cfg.n4.if_name;

  // --- IPv4 addresses (network byte order from struct in_addr::s_addr) ---
  upf::g_net_cfg.n3_ip = upf_cfg.n3.addr4.s_addr;
  upf::g_net_cfg.n6_ip = upf_cfg.n6.addr4.s_addr;
  upf::g_net_cfg.n4_ip = upf_cfg.n4.addr4.s_addr;
  upf::g_net_cfg.dn_ip = upf_cfg.remote_n6.s_addr;

  // --- Ports ---
  upf::g_net_cfg.n3_port = upf_cfg.n3.port;
  upf::g_net_cfg.n4_port = upf_cfg.n4.port;
  // TODO: upf_cfg.n6.port not yet exposed by the YAML parser; uncomment once
  // available:
  //   upf::g_net_cfg.n6_port = upf_cfg.n6.port;

  // --- Feature flags ---
  upf::g_net_cfg.bpf_datapath   = upf_cfg.enable_bpf_datapath;
  upf::g_net_cfg.qos            = upf_cfg.enable_qos;
  upf::g_net_cfg.urr            = upf_cfg.enable_urr;
  upf::g_net_cfg.bar            = upf_cfg.enable_bar;
  upf::g_net_cfg.mar            = upf_cfg.enable_mar;
  upf::g_net_cfg.framed_routing = upf_cfg.enable_fr;
  // upf_cfg uses a bool (enable_eth_pdu); normalise to "ethernet" / "ip" so
  // downstream code can compare without knowing the upf_config representation.
  upf::g_net_cfg.pdu_session_type = upf_cfg.enable_eth_pdu ? "ethernet" : "ip";

  // --- BPF map sizing ---
  upf::g_net_cfg.max_pdu_sessions         = upf_cfg.max_pdu_sessions;
  upf::g_net_cfg.max_pdrs_per_pdu_session = upf_cfg.max_pdrs_per_pdu_session;
  upf::g_net_cfg.max_sdf_filters_per_pdu_session =
      upf_cfg.max_sdf_filters_per_pdu_session;
  upf::g_net_cfg.max_upf_interfaces = upf_cfg.max_upf_interfaces;
  upf::g_net_cfg.max_upf_redirect_interfaces =
      upf_cfg.max_upf_redirect_interfaces;
  upf::g_net_cfg.max_arp_entries = upf_cfg.max_arp_entries;

  // Logger::upf_app().info(
  //     "Network config ready: N3 = %s  N6 = %s  N4 = %s",
  //     upf::GetN3Iface().c_str(), upf::GetN6Iface().c_str(),
  //     upf::GetN4Iface().c_str());

  // Logger::upf_app().info(
  //     "Features: BPF = %s QoS = %s URR = %s BAR = %s MAR = %s FR = %s PDU =
  //     %s", upf::IsBpfDatapathEnabled() ? "on" : "off", upf::IsQosEnabled() ?
  //     "on" : "off", upf::IsUrrEnabled() ? "on" : "off", upf::IsBarEnabled() ?
  //     "on" : "off", upf::IsMarEnabled() ? "on" : "off",
  //     upf::IsFramedRoutingEnabled() ? "on" : "off",
  //     upf::GetPduSessionType().c_str());

  // Logger::upf_app().info(
  //     "Map sizing: sessions = %u pdrs/session = %u sdf/session = %u arp =
  //     %u", upf::GetMaxPduSessions(), upf::GetMaxPdrsPerSession(),
  //     upf::GetMaxSdfFiltersPerSession(), upf::GetMaxArpEntries());
}
