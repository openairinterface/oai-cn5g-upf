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

#include "startup_banner.hpp"
#include "version_utils.h"
#include "logger.hpp"
#include "upf_config.hpp"
#include <arpa/inet.h>
#include <net/if.h>
#include <spdlog/spdlog.h>

using namespace oai::config;

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
void DisplayConfigSummary(const upf_config& cfg) {
  // Convert log_level enum to string
  std::string log_level_str =
      spdlog::level::to_string_view(cfg.log_level).data();

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
void DisplayNetworkInterfaces(const upf_config& cfg) {
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

  // N3 interface
  char n3_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &cfg.n3.addr4.s_addr, n3_ip, INET_ADDRSTRLEN);
  int n3_ifindex = if_nametoindex(cfg.n3.if_name.c_str());
  Logger::upf_app().startup(
      "│ N3 (GTP-U)       │ %-20s │ %-17s │ %-13d │", cfg.n3.if_name.c_str(),
      n3_ip, n3_ifindex);

  // N4 interface
  char n4_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &cfg.n4.addr4.s_addr, n4_ip, INET_ADDRSTRLEN);
  int n4_ifindex = if_nametoindex(cfg.n4.if_name.c_str());
  Logger::upf_app().startup(
      "│ N4 (PFCP)        │ %-20s │ %-17s │ %-13d │", cfg.n4.if_name.c_str(),
      n4_ip, n4_ifindex);

  // N6 interface
  char n6_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &cfg.n6.addr4.s_addr, n6_ip, INET_ADDRSTRLEN);
  int n6_ifindex = if_nametoindex(cfg.n6.if_name.c_str());
  Logger::upf_app().startup(
      "│ N6 (Data Network)│ %-20s │ %-17s │ %-13d │", cfg.n6.if_name.c_str(),
      n6_ip, n6_ifindex);

  Logger::upf_app().startup(
      "└──────────────────┴──────────────────────┴───────────────────┴─────────"
      "──────┘");
  Logger::upf_app().startup("");
}

//------------------------------------------------------------------------------
void DisplayDataPlaneStatus(const upf_config& cfg) {
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
      cfg.enable_bpf_datapath ? "✓ Enabled" : "✗ Disabled");
  Logger::upf_app().startup(
      "│ QoS Enforcement (TC-BPF)             │ %-36s │",
      cfg.enable_qos ? "✓ Enabled" : "✗ Disabled");
  Logger::upf_app().startup(
      "│ Source NAT (SNAT)                    │ %-36s │",
      cfg.enable_snat ? "✓ Enabled" : "✗ Disabled");
  Logger::upf_app().startup(
      "│ Framed Routing                       │ %-36s │",
      cfg.enable_fr ? "✓ Enabled" : "✗ Disabled");

  Logger::upf_app().startup(
      "│ Usage Reporting                      │ %-36s │",
      cfg.enable_urr ? "✓ Enabled" : "✗ Disabled");

  Logger::upf_app().startup(
      "│ Packet Buffering                     │ %-36s │",
      cfg.enable_bar ? "✓ Enabled" : "✗ Disabled");

  Logger::upf_app().startup(
      "│ Multi Access                         │ %-36s │",
      cfg.enable_mar ? "✓ Enabled" : "✗ Disabled");

  Logger::upf_app().startup(
      "│ Ethernet PDU Sessions                │ %-36s │",
      cfg.enable_eth_pdu ? "✓ Enabled" : "✗ Disabled");

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
      "│ session_by_ue_ip_map                 │ %-36d │", cfg.max_pdu_sessions);
  Logger::upf_app().startup(
      "│ pdrs_per_session_map                 │ %-36d │",
      cfg.max_pdrs_per_pdu_session);
  Logger::upf_app().startup(
      "│ qos_flows_per_session_map            │ %-36d │",
      cfg.max_qos_flows_per_pdu_session);
  Logger::upf_app().startup(
      "│ arp_table_map                        │ %-36d │", cfg.max_arp_entries);
  Logger::upf_app().startup(
      "│ rules_match_pdr_map                  │ %-36d │",
      cfg.max_pdu_sessions * cfg.max_pdrs_per_pdu_session);
  Logger::upf_app().startup(
      "│ session_qos_enabled_map              │ %-36d │", cfg.max_pdu_sessions);
  Logger::upf_app().startup(
      "│ sdf_filters_map                      │ %-36d │",
      cfg.max_sdf_filters_per_pdu_session);

  Logger::upf_app().startup(
      "│ upf_interface_map                    │ %-36d │",
      cfg.max_upf_interfaces);

  Logger::upf_app().startup(
      "│ redirect_interfaces_map              │ %-36d │",
      cfg.max_upf_redirect_interfaces);

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
    const upf_config& cfg, const std::string& n3_xdp_mode,
    const std::string& n6_xdp_mode, size_t total_maps) {
  // Check if both interfaces use native XDP
  bool both_native = (n3_xdp_mode == "Native (Hardware)") &&
                     (n6_xdp_mode == "Native (Hardware)");

  // Get QoS status
  bool qos_enabled = cfg.enable_qos;

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
      qos_enabled ? "✓ Enabled" : "✗ Disabled");
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
