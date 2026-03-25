/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "startup_banner.hpp"
#include "upf_network_config.h"  // upf::g_net_cfg, upf::Get*()/Is*()
#include "version_utils.h"
#include "number_utils.hpp"
#include "common_root_types.h"
#include "tail_call_types.h"
#include "logger.hpp"
#include <arpa/inet.h>
#include <net/if.h>
#include <spdlog/spdlog.h>
#include <iomanip>
#include <sstream>
#include <vector>

using namespace oai::utils;

//------------------------------------------------------------------------------
void DisplayStartupBanner() {
  using namespace oai::upf::utils;

  // Get version information
  auto pkg_info              = GetPackageInfo();
  std::string build_date     = GetBuildDate();
  std::string build_time     = GetBuildTime();
  std::string kernel         = GetKernelVersion();
  std::string libbpf         = GetLibbpfVersion();
  std::string system_uptime  = GetSystemUptime();
  std::string process_uptime = GetProcessUptime();
  std::string compiler       = GetCompilerVersion();
  std::string arch           = GetArchitecture();
  std::string bug_email      = GetBugReportEmail();

  // Main header
  Logger::upf_app().startup(
      "========================================================================"
      "========");
  Logger::upf_app().startup(
      "                     5G User Plane Function (UPF)");
  Logger::upf_app().startup("                        OpenAirInterface");
  Logger::upf_app().startup("                      3GPP Rel-16 Compliant");
  Logger::upf_app().startup(
      "========================================================================"
      "========");
  Logger::upf_app().startup("");

  // Version Information Table
  Logger::upf_app().startup(
      "┌───────────────────────────────────────────────────────────────────────"
      "──────┐");
  Logger::upf_app().startup(
      "│                           VERSION INFORMATION                         "
      "      │");
  Logger::upf_app().startup(
      "├──────────────────────────────┬────────────────────────────────────────"
      "──────┤");
  Logger::upf_app().startup(
      "│ Git Branch                   │ %-44s │", pkg_info.branch.c_str());
  Logger::upf_app().startup(
      "│ Git Commit Hash              │ %-44s │", pkg_info.commit_hash.c_str());
  Logger::upf_app().startup(
      "│ Git Commit Date              │ %-44s │", pkg_info.commit_date.c_str());
  Logger::upf_app().startup(
      "│ Build Time                   │ %-44s │",
      (build_date + " " + build_time).c_str());
  Logger::upf_app().startup(
      "│ 3GPP Release                 │ %-44s │", "Rel-16");
  Logger::upf_app().startup(
      "├──────────────────────────────┼────────────────────────────────────────"
      "──────┤");
  Logger::upf_app().startup(
      "│ Kernel Version               │ %-44s │", kernel.c_str());
  Logger::upf_app().startup(
      "│ libbpf Version               │ %-44s │", libbpf.c_str());
  Logger::upf_app().startup(
      "│ Compiler                     │ %-44s │", compiler.c_str());
  Logger::upf_app().startup(
      "│ Architecture                 │ %-44s │", arch.c_str());
  Logger::upf_app().startup(
      "│ System Uptime                │ %-44s │", system_uptime.c_str());
  Logger::upf_app().startup(
      "│ UPF Process Uptime           │ %-44s │", process_uptime.c_str());
  Logger::upf_app().startup(
      "├──────────────────────────────┼────────────────────────────────────────"
      "──────┤");
  Logger::upf_app().startup(
      "│ Bug Reports                  │ %-44s │", bug_email.c_str());
  Logger::upf_app().startup(
      "└──────────────────────────────┴────────────────────────────────────────"
      "──────┘");
  Logger::upf_app().startup("");
}

//------------------------------------------------------------------------------
void DisplayConfigSummary() {
  Logger::upf_app().startup(
      "┌───────────────────────────────────────────────────────────────────────"
      "──────┐");
  Logger::upf_app().startup(
      "│                    Data-Path CONFIGURATION SUMMARY          "
      "          "
      "      │");
  Logger::upf_app().startup(
      "└───────────────────────────────────────────────────────────────────────"
      "──────┘");
  Logger::upf_app().startup("");
}

//------------------------------------------------------------------------------
void DisplayNetworkInterfaces() {
  // Resolve IPs from g_net_cfg addresses
  struct in_addr n3_addr = {upf::GetN3Ip()};
  struct in_addr n4_addr = {upf::GetN4Ip()};
  struct in_addr n6_addr = {upf::GetN6Ip()};

  char n3_ip[INET_ADDRSTRLEN], n4_ip[INET_ADDRSTRLEN], n6_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &n3_addr, n3_ip, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &n4_addr, n4_ip, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &n6_addr, n6_ip, INET_ADDRSTRLEN);

  int n3_ifindex = if_nametoindex(upf::GetN3Iface().c_str());
  int n4_ifindex = if_nametoindex(upf::GetN4Iface().c_str());
  int n6_ifindex = if_nametoindex(upf::GetN6Iface().c_str());

  Logger::upf_app().startup(
      "┌───────────────────────────────────────────────────────────────────────"
      "──────┐");
  Logger::upf_app().startup(
      "│                      NETWORK INTERFACE CONFIGURATION                  "
      "      │");
  Logger::upf_app().startup(
      "├──────────────────┬──────────────────────┬───────────────────┬─────────"
      "──────┤");
  Logger::upf_app().startup(
      "│ 3GPP Ref Point   │ Interface            │ IP Address        │ ifindex "
      "      │");
  Logger::upf_app().startup(
      "├──────────────────┼──────────────────────┼───────────────────┼─────────"
      "──────┤");

  Logger::upf_app().startup(
      "│ N3 (GTP-U)       │ %-20s │ %-17s │ %-13d │", upf::GetN3Iface().c_str(),
      n3_ip, n3_ifindex);

  Logger::upf_app().startup(
      "│ N4 (PFCP)        │ %-20s │ %-17s │ %-13d │", upf::GetN4Iface().c_str(),
      n4_ip, n4_ifindex);

  Logger::upf_app().startup(
      "│ N6 (Data Network)│ %-20s │ %-17s │ %-13d │", upf::GetN6Iface().c_str(),
      n6_ip, n6_ifindex);

  Logger::upf_app().startup(
      "└──────────────────┴──────────────────────┴───────────────────┴─────────"
      "──────┘");
  Logger::upf_app().startup("");
}

//------------------------------------------------------------------------------
void DisplayDataPlaneStatus() {
  // Feature Configuration
  Logger::upf_app().startup(
      "┌───────────────────────────────────────────────────────────────────────"
      "──────┐");
  Logger::upf_app().startup(
      "│                         FEATURE CONFIGURATION                         "
      "      │");
  Logger::upf_app().startup(
      "├──────────────────────────────────────┬────────────────────────────────"
      "──────┤");
  Logger::upf_app().startup(
      "│ Feature                              │ Status                         "
      "      │");
  Logger::upf_app().startup(
      "├──────────────────────────────────────┼────────────────────────────────"
      "──────┤");
  Logger::upf_app().startup(
      "│ eBPF/XDP Data Plane                  │ %-36s │",
      upf::IsBpfDatapathEnabled() ? "✓ Enabled" : "✗ Disabled");
  Logger::upf_app().startup(
      "│ QoS Enforcement (TC-BPF)             │ %-36s │",
      upf::IsQosEnabled() ? "✓ Enabled" : "✗ Disabled");
  Logger::upf_app().startup(
      "│ Framed Routing                       │ %-36s │",
      upf::IsFramedRoutingEnabled() ? "✓ Enabled" : "✗ Disabled");
  Logger::upf_app().startup(
      "│ Usage Reporting (URR)                │ %-36s │",
      upf::IsUrrEnabled() ? "✓ Enabled" : "✗ Disabled");
  Logger::upf_app().startup(
      "│ Packet Buffering (BAR)               │ %-36s │",
      upf::IsBarEnabled() ? "✓ Enabled" : "✗ Disabled");
  Logger::upf_app().startup(
      "│ Multi-Access Steering (MAR)          │ %-36s │",
      upf::IsMarEnabled() ? "✓ Enabled" : "✗ Disabled");
  Logger::upf_app().startup(
      "│ Ethernet PDU Sessions                │ %-36s │",
      (upf::GetPduSessionType() == "ethernet") ? "✓ Enabled" : "✗ Disabled");
  Logger::upf_app().startup(
      "└──────────────────────────────────────┴────────────────────────────────"
      "──────┘");
  Logger::upf_app().startup("");
  // BPF Map Capacity Configuration
  Logger::upf_app().startup(
      "┌───────────────────────────────────────────────────────────────────────"
      "──────┐");
  Logger::upf_app().startup(
      "│                       BPF MAP CAPACITY CONFIGURATION                  "
      "      │");
  Logger::upf_app().startup(
      "├──────────────────────────────────────┬────────────────────────────────"
      "──────┤");
  Logger::upf_app().startup(
      "│ Map Name                             │ Max Entries                    "
      "      │");
  Logger::upf_app().startup(
      "├──────────────────────────────────────┼────────────────────────────────"
      "──────┤");
  Logger::upf_app().startup(
      "│ session_by_ue_ip_map                 │ %-36u │",
      upf::GetMaxPduSessions());
  Logger::upf_app().startup(
      "│ pdrs_per_session_map                 │ %-36u │",
      upf::GetMaxPdrsPerSession());
  Logger::upf_app().startup(
      "│ arp_table_map                        │ %-36u │",
      upf::GetMaxArpEntries());
  Logger::upf_app().startup(
      "│ rules_match_pdr_map                  │ %-36u │",
      upf::GetMaxPduSessions() * upf::GetMaxPdrsPerSession());
  Logger::upf_app().startup(
      "│ sdf_filters_map                      │ %-36u │",
      upf::GetMaxPduSessions() * upf::GetMaxSdfFiltersPerSession());
  Logger::upf_app().startup(
      "│ upf_interface_map                    │ %-36u │",
      upf::GetMaxUpfInterfaces());
  Logger::upf_app().startup(
      "│ redirect_interfaces_map              │ %-36u │",
      upf::GetMaxUpfRedirectInterfaces());

  Logger::upf_app().startup(
      "└──────────────────────────────────────┴────────────────────────────────"
      "──────┘");
  Logger::upf_app().startup("");
}

//------------------------------------------------------------------------------
void DisplayPipelineConfig(const PipelineFeatureFlags& flags) {
  const bool eth = (flags.pdu_type == PduSessionType::Ethernet);

  Logger::upf_app().startup(
      "┌───────────────────────────────────────────────────────────────────────"
      "──────┐");
  Logger::upf_app().startup(
      "│                   BPF TAIL-CALL PIPELINE CONFIGURATION                "
      "      │");
  Logger::upf_app().startup(
      "├──────────────────────────────────────┬────────────────────────────────"
      "──────┤");
  Logger::upf_app().startup(
      "│ Stage                                │ Status / Program               "
      "      │");
  Logger::upf_app().startup(
      "├──────────────────────────────────────┼────────────────────────────────"
      "──────┤");
  Logger::upf_app().startup(
      "│ PDU Session Type                     │ %-36s │",
      eth ? "Ethernet" : "IP");
  Logger::upf_app().startup(
      "│ N3 Entry Program                     │ %-36s │",
      eth ? "upf_n3_eth_entry" : "upf_n3_entry");
  Logger::upf_app().startup(
      "│ N6 Entry Program                     │ %-36s │",
      eth ? "upf_n6_eth_entry" : "upf_n6_entry");
  Logger::upf_app().startup(
      "├──────────────────────────────────────┼────────────────────────────────"
      "──────┤");
  Logger::upf_app().startup(
      "│ Session Lookup  [slot %-2d] (mandatory) │ %-36s │",
      PROG_SESSION_LOOKUP_IP, "✓ Loaded");
  Logger::upf_app().startup(
      "│ PDR Match       [slot %-2d] (mandatory) │ %-36s │", PROG_PDR_MATCH,
      "✓ Loaded");
  Logger::upf_app().startup(
      "│ FAR Apply       [slot %-2d] (mandatory) │ %-36s │", PROG_FAR_APPLY,
      "✓ Loaded");
  Logger::upf_app().startup(
      "├──────────────────────────────────────┼────────────────────────────────"
      "──────┤");
  Logger::upf_app().startup(
      "│ QER Enforcement [slot %-2d] (optional)  │ %-36s │", PROG_QER_APPLY,
      flags.enable_qos ? "✓ Loaded" : "— Skipped");
  Logger::upf_app().startup(
      "│ URR Reporting   [slot %-2d] (optional)  │ %-36s │", PROG_URR_APPLY,
      flags.enable_urr ? "✓ Loaded" : "— Skipped");
  Logger::upf_app().startup(
      "│ BAR Buffering   [slot %-2d] (optional)  │ %-36s │", PROG_BAR_APPLY,
      flags.enable_bar ? "✓ Loaded" : "— Skipped");
  Logger::upf_app().startup(
      "│ MAR Steering    [slot %-2d] (optional)  │ %-36s │", PROG_MAR_APPLY,
      flags.enable_mar ? "✓ Loaded" : "— Skipped");
  //   Logger::upf_app().startup(
  //       "│ Framed Routing  [slot %-2d] (optional)  │ %-36s │",
  //       PROG_FRAMED_ROUTING,
  //       flags.enable_framed_routing ? "✓ Loaded" : "— Skipped");
  //   Logger::upf_app().startup(
  //       "│ ETH Broadcast   [slot %-2d] (ETH only)  │ %-36s │",
  //       PROG_ETH_PDU_BROADCAST, eth ? "✓ Loaded" : "— Skipped");
  Logger::upf_app().startup(
      "└──────────────────────────────────────┴────────────────────────────────"
      "──────┘");
  Logger::upf_app().startup("");
}

//------------------------------------------------------------------------------
/**
 * @brief Display XDP/TC configuration summary
 *
 * @param cfg UPF configuration
 * @param n3_xdp_mode XDP mode string for N3 ("Native (Hardware)" or "SKB
 * (Software)")
 * @param n6_xdp_mode XDP mode string for N6 ("Native (Hardware)" or "SKB
 * (Software)")
 * @param total_maps Total number of BPF maps loaded
 */
void DisplayXdpConfiguration(
    const std::string& n3_xdp_mode, const std::string& n6_xdp_mode,
    size_t total_maps) {
  const bool both_native = (n3_xdp_mode == "Native (Hardware)") &&
                           (n6_xdp_mode == "Native (Hardware)");

  Logger::upf_app().startup(
      "┌───────────────────────────────────────────────────────────────────────"
      "──────┐");
  Logger::upf_app().startup(
      "│                    eBPF/XDP RUNTIME CONFIGURATION                     "
      "      │");
  Logger::upf_app().startup(
      "├──────────────────────────────────────┬────────────────────────────────"
      "──────┤");
  Logger::upf_app().startup(
      "│ Component                            │ Status                         "
      "      │");
  Logger::upf_app().startup(
      "├──────────────────────────────────────┼────────────────────────────────"
      "──────┤");
  Logger::upf_app().startup(
      "│ N3 XDP Mode                          │ %-36s │", n3_xdp_mode.c_str());
  Logger::upf_app().startup(
      "│ N6 XDP Mode                          │ %-36s │", n6_xdp_mode.c_str());
  Logger::upf_app().startup(
      "│ QoS Enforcement (TC-BPF)             │ %-36s │",
      upf::IsQosEnabled() ? "✓ Enabled" : "✗ Disabled");
  Logger::upf_app().startup(
      "│ Total BPF Maps Loaded                │ %-36zu │", total_maps);
  Logger::upf_app().startup(
      "├──────────────────────────────────────┼────────────────────────────────"
      "──────┤");
  Logger::upf_app().startup(
      "│ Expected Throughput                  │ %-36s │",
      both_native ? "~10+ Gbps (Native XDP)" : "~1-2 Gbps (SKB mode)");
  Logger::upf_app().startup(
      "│ Hardware Acceleration                │ %-36s │",
      both_native ? "✓ Enabled (Native XDP)" : "SKB fallback");
  Logger::upf_app().startup(
      "└──────────────────────────────────────┴────────────────────────────────"
      "──────┘");
  Logger::upf_app().startup("");
}

//------------------------------------------------------------------------------
void DisplayReadyMessage() {
  sleep(5);
  Logger::upf_app().startup(
      "========================================================================"
      "========");
  Logger::upf_app().startup(
      "                   UPF DATA-PATH INITIALIZATION COMPLETE - READY");
  Logger::upf_app().startup(
      "         Waiting for PFCP Session Establishment requests on N4...");
  Logger::upf_app().startup(
      "========================================================================"
      "========");
  Logger::upf_app().startup("");
}

//------------------------------------------------------------------------------

/*
 * QOS VISUALIZATION -
 */

void DisplayQosFlowTable(
    uint64_t seid, const std::vector<QosFlowInfo>& qos_flows) {
  auto& logger = Logger::upf_app();

  logger.info("");
  logger.info(
      "  "
      "┌───────────────────────────────────────────────────────────────────────"
      "───────────────────────────────────┐");
  logger.info(
      "  │                                      QoS FLOWS - Session " SEID_FMT
      "                                             │",
      seid);
  logger.info(
      "  "
      "├──────┬─────┬──────────────┬────────────┬────────────┬─────────────────"
      "───────────────────────────────────┤");
  logger.info(
      "  │ QER  │ QFI │    Class     │ GBR (kbps) │ MBR (kbps) │ "
      "              Flow "
      "Description                     │");
  logger.info(
      "  "
      "├──────┼─────┼──────────────┼────────────┼────────────┼─────────────────"
      "───────────────────────────────────┤");

  for (const auto& flow : qos_flows) {
    std::string desc = flow.flow_description;
    if (desc.empty()) {
      desc = "Default QoS Flow";
    }
    if (desc.length() > 50) {
      desc = desc.substr(0, 47) + "...";
    }

    logger.info(
        "  │ %-4u │ %-3u │ 1:%-5u      │ %-10s │ %-10s │ %-50s │", flow.qer_id,
        flow.qfi, flow.class_id, FormatNumber(flow.rate_kbps).c_str(),
        FormatNumber(flow.ceil_kbps).c_str(), desc.c_str());
  }

  logger.info(
      "  "
      "└──────┴─────┴──────────────┴────────────┴────────────┴─────────────────"
      "───────────────────────────────────┘");
  logger.info("");
}

//------------------------------------------------------------------------------
void LogQosSetupStart(uint64_t seid, const std::string& interface) {
  Logger::upf_app().info("");
  Logger::upf_app().info(
      "  ┌───────────────────────────────────────────────────┐");
  Logger::upf_app().info(
      "  │            QoS ENFORCEMENT SETUP                  │");
  Logger::upf_app().info(
      "  │       Session: " SEID_FMT ", Interface: %-14s     │", seid,
      interface.c_str());
  Logger::upf_app().info(
      "  └───────────────────────────────────────────────────┘");
}

//------------------------------------------------------------------------------
void LogQosSetupComplete(uint64_t seid, int num_qos_flows, bool has_errors) {
  auto& logger = Logger::upf_app();

  if (has_errors) {
    logger.warn("");
    logger.warn("  ┌───────────────────────────────────────────────────┐");
    logger.warn("  │  QoS ENFORCEMENT SETUP - COMPLETED WITH WARNINGS  │");
    logger.warn(
        "  │      Session " SEID_FMT ": %d QoS Flow(s) configured        │",
        seid, num_qos_flows);
    logger.warn("  │   Some TC operations failed (see warnings above)  │");
    logger.warn("  └───────────────────────────────────────────────────┘");
  } else {
    logger.info("");
    logger.info("  ┌───────────────────────────────────────────────────┐");
    logger.info("  │           QoS ENFORCEMENT COMPLETED               │");
    logger.info(
        "  │      Session " SEID_FMT ": %d QoS Flow(s) configured        │",
        seid, num_qos_flows);
    logger.info("  └───────────────────────────────────────────────────┘");
  }
  logger.info("");
}
