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
#include "upf_network_config.h"
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
      "======================================================================"
      "========");

  Logger::upf_app().startup(
      "                     5G User Plane Function (UPF)");
  Logger::upf_app().startup("                        OpenAirInterface");
  Logger::upf_app().startup("                      3GPP Rel-17 Compliant");
  Logger::upf_app().startup(
      "======================================================================"
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
      "│ 3GPP Release                 │ %-44s │", "Rel-17");
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

  const bool is_eth = (upf::GetPduSessionType() == "ethernet");

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

  // ── Session / pipeline maps (always present)
  Logger::upf_app().startup(
      "│ session_by_ue_ip_map                 │ %-36u │",
      upf::GetMaxPduSessions());
  Logger::upf_app().startup(
      "│ session_rules_enabled_map            │ %-36u │",
      upf::GetMaxPduSessions());
  Logger::upf_app().startup(
      "│ pdrs_per_session_map                 │ %-36u │",
      upf::GetMaxPdrsPerSession());
  Logger::upf_app().startup(
      "│ rules_match_pdr_map                  │ %-36u │",
      upf::GetMaxPduSessions() * upf::GetMaxPdrsPerSession());
  Logger::upf_app().startup(
      "│ sdf_filters_map                      │ %-36u │",
      upf::GetMaxPduSessions() * upf::GetMaxSdfFiltersPerSession());

  // ── Interface / ARP maps (always present)
  Logger::upf_app().startup(
      "│ upf_interface_map                    │ %-36u │",
      upf::GetMaxUpfInterfaces());
  Logger::upf_app().startup(
      "│ redirect_interfaces_map              │ %-36u │",
      upf::GetMaxUpfRedirectInterfaces());
  Logger::upf_app().startup(
      "│ arp_table_map                        │ %-36u │",
      upf::GetMaxArpEntries());

  // ── QER / TC maps (only if QoS enforcement enabled)
  if (upf::IsQosEnabled())
    Logger::upf_app().startup(
        "│ egress_ifindex                       │ %-36u │",
        upf::GetMaxUpfInterfaces());

  // ── Ethernet PDU session maps (only if ETH PDU sessions enabled)
  if (is_eth) {
    Logger::upf_app().startup(
        "│ eth_session_mapping_map              │ %-36u │",
        upf::GetMaxPduSessions());
    Logger::upf_app().startup(
        "│ eth_session_pdrs_map                 │ %-36u │",
        upf::GetMaxPduSessions());
    Logger::upf_app().startup(
        "│ eth_rules_match_pdr_map              │ %-36u │",
        upf::GetMaxPduSessions() * upf::GetMaxPdrsPerSession());
    Logger::upf_app().startup(
        "│ eth_egress_ifindex_map               │ %-36u │",
        upf::GetMaxUpfInterfaces());
    Logger::upf_app().startup(
        "│ mac_pdu_session_map                  │ %-36u │",
        upf::GetMaxPduSessions());
  }

  // ── URR maps (only if URR enabled)
  if (upf::IsUrrEnabled()) {
    Logger::upf_app().startup(
        "│ urr_config_map                       │ %-36u │",
        upf::GetMaxPduSessions());
    Logger::upf_app().startup(
        "│ urr_volume_counters_map              │ %-36u │",
        upf::GetMaxPduSessions());
    Logger::upf_app().startup(
        "│ urr_report_ringbuf_map               │ %-36s │", "256 KB (ringbuf)");
  }

  // ── BAR maps (only if BAR enabled)
  if (upf::IsBarEnabled()) {
    Logger::upf_app().startup(
        "│ bar_config_map                       │ %-36u │",
        upf::GetMaxPduSessions());
    Logger::upf_app().startup(
        "│ bar_state_map                        │ %-36u │",
        upf::GetMaxPduSessions());
    Logger::upf_app().startup(
        "│ bar_ddn_ringbuf_map                  │ %-36s │", "64 KB (ringbuf)");
  }

  // ── MAR maps (only if MAR enabled)
  if (upf::IsMarEnabled()) {
    Logger::upf_app().startup(
        "│ mar_config_map                       │ %-36u │",
        upf::GetMaxPduSessions());
    Logger::upf_app().startup(
        "│ mar_access_state_map                 │ %-36u │",
        upf::GetMaxPduSessions());
  }

  Logger::upf_app().startup(
      "└──────────────────────────────────────┴────────────────────────────────"
      "──────┘");
  Logger::upf_app().startup("");
}

//------------------------------------------------------------------------------
void DisplayPipelineCreationTree(const PipelineFeatureFlags& flags) {
  const bool eth = (flags.pdu_type == PduSessionType::Ethernet);

  Logger::upf_app().info("");
  Logger::upf_app().info(" Interface attachment (XDP hook)");

  // ── Entry programs (hooked to interfaces)
  if (!eth) {
    Logger::upf_app().info(
        "  ├─ N3EntryProgram:            created  (iface=%s, dir=UL, XDP)",
        upf::GetN3Iface().c_str());
    Logger::upf_app().info(
        "  └─ N6EntryProgram:            created  (iface=%s, dir=DL, XDP)",
        upf::GetN6Iface().c_str());
  } else {
    Logger::upf_app().info(
        "  ├─ N3EthEntryProgram:         created  (iface=%s, dir=UL, XDP)",
        upf::GetN3Iface().c_str());
    Logger::upf_app().info(
        "  └─ N6EthEntryProgram:         created  (iface=%s, dir=DL, XDP)",
        upf::GetN6Iface().c_str());
  }

  Logger::upf_app().info("");
  Logger::upf_app().info(" Tail-call pipeline (shared prog_array)");

  // ── Mandatory pipeline stages
  if (!eth) {
    Logger::upf_app().info(
        "  ├─ SessionLookupIPProgram:    created  (session-lkp, XDP, slot=%d)",
        PROG_SESSION_LOOKUP_IP);
  } else {
    Logger::upf_app().info(
        "  ├─ SessionLookupETHProgram:   created  (session-lkp, XDP, slot=%d)",
        PROG_SESSION_LOOKUP_IP);
  }
  Logger::upf_app().info(
      "  ├─ PdrMatchProgram:           created  (rule-match,  XDP, slot=%d)",
      PROG_PDR_MATCH);
  Logger::upf_app().info(
      "  ├─ FARProgram:                created  (rule-apply,  XDP, slot=%d)",
      PROG_FAR_APPLY);

  // ── Optional pipeline stages
  if (flags.enable_qer) {
    Logger::upf_app().info(
        "  ├─ QERProgram:                created  (rule-apply,  XDP, slot=%d)",
        PROG_QER_APPLY);
    Logger::upf_app().info(
        "  │   └─ QERTCProgram:          created  (qos-enforce, TC,  "
        "per-session)");
  }
  if (flags.enable_urr) {
    Logger::upf_app().info(
        "  ├─ URRProgram:                created  (rule-apply,  XDP, slot=%d)",
        PROG_URR_APPLY);
  }
  if (flags.enable_bar) {
    Logger::upf_app().info(
        "  ├─ BARProgram:                created  (rule-apply,  XDP, slot=%d)",
        PROG_BAR_APPLY);
  }

  // MAR is always last — use └─
  if (flags.enable_mar) {
    Logger::upf_app().info(
        "  └─ MARProgram:                created  (rule-apply,  XDP, slot=%d)",
        PROG_MAR_APPLY);
  } else if (!flags.enable_bar && !flags.enable_urr) {
    // FAR was the last printed — already used ├─, nothing to close
  }

  Logger::upf_app().info("");
}

//------------------------------------------------------------------------------
void DisplayPipelineLoadTree(const std::vector<ProgramLoadInfo>& programs) {
  // ── Partition: entry programs (have iface) vs pipeline stages
  std::vector<const ProgramLoadInfo*> entries, stages;
  for (const auto& p : programs) {
    if (!p.iface.empty())
      entries.push_back(&p);
    else
      stages.push_back(&p);
  }

  // ── Section 1: Interface attachment
  Logger::upf_app().info("");
  Logger::upf_app().info(" Interface attachment (XDP hook)");
  for (size_t i = 0; i < entries.size(); i++) {
    const auto& p   = *entries[i];
    const char* pfx = (i + 1 == entries.size()) ? "  └─" : "  ├─";
    Logger::upf_app().info(
        "%s %-28s loaded ✓  (%zu maps, iface=%s)", pfx, (p.name + ":").c_str(),
        p.map_count, p.iface.c_str());
  }

  // ── Section 2: Tail-call pipeline
  Logger::upf_app().info("");
  Logger::upf_app().info(" Tail-call pipeline (shared prog_array)");
  for (size_t i = 0; i < stages.size(); i++) {
    const auto& p = *stages[i];

    if (p.is_child) {
      // QERTCProgram -- child of QERProgram
      Logger::upf_app().info(
          "  │   └─ %-24s loaded ✓  (TC-BPF, per-session)",
          (p.name + ":").c_str());
      continue;
    }

    // Check if last non-child stage
    bool last_stage = true;
    for (size_t j = i + 1; j < stages.size(); j++) {
      if (!stages[j]->is_child) {
        last_stage = false;
        break;
      }
    }
    const char* pfx = last_stage ? "  └─" : "  ├─";
    Logger::upf_app().info(
        "%s %-28s loaded ✓  (%zu maps)", pfx, (p.name + ":").c_str(),
        p.map_count);
  }
  Logger::upf_app().info("");
}

//------------------------------------------------------------------------------
void DisplayPipelineConfig(const PipelineFeatureFlags& flags) {
  const bool eth = (flags.pdu_type == PduSessionType::Ethernet);

  // ── TABLE 1: Pipeline program list

  const char* loaded  = "✓ loaded ";
  const char* skipped = "— skipped";
  char slot_buf[4];

  Logger::upf_app().startup(
      "┌──────────────────────────────────────┬────────────┬────────────┬──────"
      "──────┐");
  Logger::upf_app().startup(
      "│ %-36s │ %-10s │ %-10s │ %-10s │", "Program", "Dispatch", "Slot",
      "Status");

  Logger::upf_app().startup(
      "├──────────────────────────────────────┴────────────┴────────────┴──────"
      "──────┤");

  // Full-span PDU info row
  {
    char buf[128];
    // snprintf(
    //     buf, sizeof(buf), "          PDU Session : %-10s  N3 = %-14s  N6 =
    //     %s", eth ? "Ethernet" : "IP", upf::GetN3Iface().c_str(),
    //     upf::GetN6Iface().c_str());
    const char* pdu = eth ? "Ethernet" : "IP";
    const char* n3  = upf::GetN3Iface().c_str();
    const char* n6  = upf::GetN6Iface().c_str();

    int fixed =
        14 + (int) strlen(pdu) + 5 + (int) strlen(n3) + 5 + (int) strlen(n6);
    int remaining = 77 - fixed;     // total space to distribute
    int m         = remaining / 5;  // small: left/right margin (~1/5 each)
    int g         = (remaining - 2 * m) / 2;  // large: gap between items
    int extra = remaining - 2 * m - 2 * g;    // 0 or 1, absorb in right margin

    snprintf(
        buf, sizeof(buf), "%*sPDU Session : %s%*sN3 = %s%*sN6 = %s%*s", m, "",
        pdu, g, "", n3, g, "", n6, m + extra, "");
    Logger::upf_app().startup("│%-77s│", buf);
  }

  Logger::upf_app().startup(
      "├──────────────────────────────────────┬────────────┬────────────┬──────"
      "──────┤");

  // ── XDP-hook entry programs
  Logger::upf_app().startup(
      "│ %-36s │ %-10s │ %-10s │ %-10s │",
      eth ? "N3EthEntryProgram" : "N3EntryProgram", "XDP hook", "-", loaded);
  Logger::upf_app().startup(
      "│ %-36s │ %-10s │ %-10s │ %-10s │",
      eth ? "N6EthEntryProgram" : "N6EntryProgram", "XDP hook", "-", loaded);

  Logger::upf_app().startup(
      "├───────────────────────────────────────────────────────────────────────"
      "──────┤");
  Logger::upf_app().startup(
      "│%-77s│",
      "        Tail-call pipeline  (shared prog_array, XDP driver context)");
  Logger::upf_app().startup(
      "├──────────────────────────────────────┬────────────┬────────────┬──────"
      "──────┤");

  // ── Tail-call pipeline stages
  snprintf(slot_buf, sizeof(slot_buf), "%d", PROG_SESSION_LOOKUP_IP);
  Logger::upf_app().startup(
      "│ %-36s │ %-10s │ %-10s │ %-10s │",
      eth ? "SessionLookupETHProgram" : "SessionLookupIPProgram", "tail-call",
      slot_buf, loaded);
  snprintf(slot_buf, sizeof(slot_buf), "%d", PROG_PDR_MATCH);
  Logger::upf_app().startup(
      "│ %-36s │ %-10s │ %-10s │ %-10s │", "PdrMatchProgram", "tail-call",
      slot_buf, loaded);
  snprintf(slot_buf, sizeof(slot_buf), "%d", PROG_FAR_APPLY);
  Logger::upf_app().startup(
      "│ %-36s │ %-10s │ %-10s │ %-10s │", "FARProgram", "tail-call", slot_buf,
      loaded);
  snprintf(slot_buf, sizeof(slot_buf), "%d", PROG_QER_APPLY);
  Logger::upf_app().startup(
      "│ %-36s │ %-10s │ %-10s │ %-10s │", "QERProgram", "tail-call", slot_buf,
      flags.enable_qer ? loaded : skipped);
  Logger::upf_app().startup(
      "│ %-36s │ %-10s │ %-10s │ %-10s │", "QERTCProgram", "TC hook", "TC",
      flags.enable_qer ? loaded : skipped);
  snprintf(slot_buf, sizeof(slot_buf), "%d", PROG_URR_APPLY);
  Logger::upf_app().startup(
      "│ %-36s │ %-10s │ %-10s │ %-10s │", "URRProgram", "tail-call", slot_buf,
      flags.enable_urr ? loaded : skipped);
  snprintf(slot_buf, sizeof(slot_buf), "%d", PROG_BAR_APPLY);
  Logger::upf_app().startup(
      "│ %-36s │ %-10s │ %-10s │ %-10s │", "BARProgram", "tail-call", slot_buf,
      flags.enable_bar ? loaded : skipped);
  snprintf(slot_buf, sizeof(slot_buf), "%d", PROG_MAR_APPLY);
  Logger::upf_app().startup(
      "│ %-36s │ %-10s │ %-10s │ %-10s │", "MARProgram", "tail-call", slot_buf,
      flags.enable_mar ? loaded : skipped);

  Logger::upf_app().startup(
      "└──────────────────────────────────────┴────────────┴────────────┴──────"
      "──────┘");
  Logger::upf_app().startup("");

  // ── TABLE 2: BPF Map × Program matrix
  const char* y  = " ✓";
  const char* nu = "  ";

  // Program column abbreviations:
  // N3=N3Entry  N6=N6Entry  SLk=SessionLookupIP  PDR=PdrMatch
  // FAR=FARProgram  QER=QERProgram  QTC=QERTCProgram
  // URR=URRProgram  BAR=BARProgram  MAR=MARProgram

  Logger::upf_app().startup(
      "┌───────────────────────────┬────┬────┬────┬────┬────┬────┬────┬────┬───"
      "─┬────┐");
  Logger::upf_app().startup(
      "│ %-25s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s "
      "│ %-2s │",
      "BPF Map", "N3", "N6", "SLk", "PDR", "FAR", "QER", "QTC", "URR", "BAR",
      "MAR");
  Logger::upf_app().startup(
      "├───────────────────────────┴────┴────┴────┴────┴────┴────┴────┴────┴───"
      "─┴────┤");
  Logger::upf_app().startup("│%-77s│", "  shared infrastructure");
  Logger::upf_app().startup(
      "├───────────────────────────┬────┬────┬────┬────┬────┬────┬────┬────┬───"
      "─┬────┤");

  //                                     N3    N6    SeLk  PDRm  FAR   QER QRTC
  //                                     URR   BAR   MAR
  Logger::upf_app().startup(
      "│ %-25s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s "
      "│ %-2s │",
      "tail_call_progs_map", y, y, y, nu, nu, nu, nu, nu, nu, nu);
  Logger::upf_app().startup(
      "│ %-25s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s "
      "│ %-2s │",
      "packet_context_map", y, y, y, y, y, y, nu, y, y, y);
  Logger::upf_app().startup(
      "│ %-25s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s "
      "│ %-2s │",
      "mc_stats_map", y, y, y, y, y, y, nu, y, y, y);

  Logger::upf_app().startup(
      "├───────────────────────────┴────┴────┴────┴────┴────┴────┴────┴────┴───"
      "─┴────┤");
  Logger::upf_app().startup("│%-77s│", "  session / pipeline");
  Logger::upf_app().startup(
      "├───────────────────────────┬────┬────┬────┬────┬────┬────┬────┬────┬───"
      "─┬────┤");

  Logger::upf_app().startup(
      "│ %-25s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s "
      "│ %-2s │",
      "session_by_ue_ip_map", nu, nu, y, nu, nu, nu, nu, nu, nu, nu);
  Logger::upf_app().startup(
      "│ %-25s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s "
      "│ %-2s │",
      "session_rules_enabled_map", nu, nu, y, nu, nu, nu, nu, nu, nu, nu);
  Logger::upf_app().startup(
      "│ %-25s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s "
      "│ %-2s │",
      "pdrs_per_session_map", nu, nu, nu, y, nu, nu, nu, nu, nu, nu);
  Logger::upf_app().startup(
      "│ %-25s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s "
      "│ %-2s │",
      "sdf_filters_map", nu, nu, nu, y, nu, nu, nu, nu, nu, nu);
  Logger::upf_app().startup(
      "│ %-25s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s "
      "│ %-2s │",
      "rules_match_pdr_map", nu, nu, nu, nu, y, y, nu, nu, nu, nu);

  Logger::upf_app().startup(
      "├───────────────────────────┴────┴────┴────┴────┴────┴────┴────┴────┴───"
      "─┴────┤");
  Logger::upf_app().startup("│%-77s│", "  interface / ARP");
  Logger::upf_app().startup(
      "├───────────────────────────┬────┬────┬────┬────┬────┬────┬────┬────┬───"
      "─┬────┤");

  Logger::upf_app().startup(
      "│ %-25s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s "
      "│ %-2s │",
      "upf_interface_map", nu, nu, nu, nu, y, nu, nu, nu, nu, y);
  Logger::upf_app().startup(
      "│ %-25s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s "
      "│ %-2s │",
      "redirect_interfaces_map", nu, nu, nu, nu, y, nu, nu, nu, nu, y);
  Logger::upf_app().startup(
      "│ %-25s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s "
      "│ %-2s │",
      "arp_table_map", nu, nu, nu, nu, y, nu, nu, nu, nu, nu);
  Logger::upf_app().startup(
      "│ %-25s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s "
      "│ %-2s │",
      "egress_ifindex", nu, nu, nu, nu, nu, nu, y, nu, nu, nu);

  Logger::upf_app().startup(
      "├───────────────────────────┴────┴────┴────┴────┴────┴────┴────┴────┴───"
      "─┴────┤");
  Logger::upf_app().startup("│%-77s│", "  URR / BAR / MAR");
  Logger::upf_app().startup(
      "├───────────────────────────┬────┬────┬────┬────┬────┬────┬────┬────┬───"
      "─┬────┤");

  Logger::upf_app().startup(
      "│ %-25s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s "
      "│ %-2s │",
      "urr_config_map", nu, nu, nu, nu, nu, nu, nu, y, nu, nu);
  Logger::upf_app().startup(
      "│ %-25s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s "
      "│ %-2s │",
      "urr_volume_counters_map", nu, nu, nu, nu, nu, nu, nu, y, nu, nu);
  Logger::upf_app().startup(
      "│ %-25s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s "
      "│ %-2s │",
      "urr_report_ringbuf_map", nu, nu, nu, nu, nu, nu, nu, y, nu, nu);
  Logger::upf_app().startup(
      "│ %-25s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s "
      "│ %-2s │",
      "bar_config_map", nu, nu, nu, nu, nu, nu, nu, nu, y, nu);
  Logger::upf_app().startup(
      "│ %-25s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s "
      "│ %-2s │",
      "bar_state_map", nu, nu, nu, nu, nu, nu, nu, nu, y, nu);
  Logger::upf_app().startup(
      "│ %-25s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s "
      "│ %-2s │",
      "bar_ddn_ringbuf_map", nu, nu, nu, nu, nu, nu, nu, nu, y, nu);
  Logger::upf_app().startup(
      "│ %-25s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s "
      "│ %-2s │",
      "mar_config_map", nu, nu, nu, nu, nu, nu, nu, nu, nu, y);
  Logger::upf_app().startup(
      "│ %-25s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s │ %-2s "
      "│ %-2s │",
      "mar_access_state_map", nu, nu, nu, nu, nu, nu, nu, nu, nu, y);

  Logger::upf_app().startup(
      "└───────────────────────────┴────┴────┴────┴────┴────┴────┴────┴────┴───"
      "─┴────┘");
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
//------------------------------------------------------------------------------
// DisplayDataPathArchitecture
// Draws the full XDP/TC pipeline with L-shaped centre-to-centre arrows.
// Optional stages (QER, URR, BAR, MAR) are only rendered when enabled;
// the routing logic adapts automatically to every combination.
//------------------------------------------------------------------------------
void DisplayDataPathArchitecture(const PipelineFeatureFlags& flags) {
  auto& log      = Logger::upf_app();
  const bool eth = (flags.pdu_type == PduSessionType::Ethernet);

  // ── ANSI colour codes (256-colour palette, 1 = bold)
  const std::string R  = "\033[0m";
  const std::string BX = "\033[38;5;238m";  // dark grey  – borders
  const std::string AR = "\033[38;5;60m";  // slate      – arrows / connectors
  const std::string ACT  = "\033[38;5;241m";    // muted      – action text
  const std::string MAP  = "\033[38;5;61m";     // slate-blue – map refs
  const std::string COND = "\033[38;5;239m";    // dim grey   – conditions
  const std::string N3C  = "\033[1;38;5;42m";   // teal bold  – N3
  const std::string N6C  = "\033[1;38;5;79m";   // cyan bold  – N6
  const std::string SLC  = "\033[1;38;5;111m";  // lavender   – SessionLookup
  const std::string PDC  = "\033[1;38;5;68m";   // blue       – PdrMatch
  const std::string FAC  = "\033[1;38;5;173m";  // coral      – FAR
  const std::string QEC  = "\033[1;38;5;111m";  // purple     – QER
  const std::string URC  = "\033[1;38;5;42m";   // green      – URR
  const std::string BAC  = "\033[1;38;5;42m";   // green      – BAR
  const std::string MAC  = "\033[1;38;5;79m";   // teal       – MAR
  const std::string TCC  = "\033[1;38;5;179m";  // amber      – QERTC
  const std::string RDC  = "\033[1;38;5;173m";  // coral bold – XDP_REDIRECT
  const std::string TE   = "\033[38;5;29m";     // tag: entry-point
  const std::string TS2  = "\033[38;5;61m";     // tag: session-lkp / rule-apply
  const std::string TP   = "\033[38;5;25m";  // tag: rule-match / rule-apply FAR
  const std::string TT   = "\033[38;5;136m";  // tag: qos-enforce TC

  // ── String helpers
  auto sp = [](int n) -> std::string {
    return std::string(n > 0 ? n : 0, ' ');
  };
  auto dsh = [](int n) -> std::string {
    std::string s;
    for (int i = 0; i < n; i++) s += "─";
    return s;
  };
  auto E = [&](const std::string& s) { log.startup("%s", s.c_str()); };

  // ── Layout constants (visual columns, 0-indexed from start of line)
  //
  //  Full box  : "  │" + 77 chars + "│"  →  │ at col 2, content 3..79, │ at 80
  //  Half pair : "  │" + 30 chars + "│" + 15 chars + "│" + 30 chars + "│"
  //              left  │ at col 2,  content 3..32,  │ at 33
  //              right │ at col 49, content 50..79, │ at 80
  //
  const int FW = 77;  // full-box inner width
  const int HW = 30;  // half-box inner width
  const int G  = 15;  // gap / tail-call label width  "─ tail-call ──►"
  const int PF = 41;  // full-box  visual centre  (3 + 38 = 41)
  const int PL = 18;  // left  box visual centre  (3 + 15 = 18)
  const int PR = 65;  // right box visual centre  (50 + 15 = 65)

  // ── Box-drawing primitives ─────────────────────────────────────────────────

  // Full-width box
  auto FT = [&]() { E("  " + BX + "┌" + dsh(FW) + "┐" + R); };
  auto FS = [&]() { E("  " + BX + "├" + dsh(FW) + "┤" + R); };
  auto FB = [&]() { E("  " + BX + "└" + dsh(FW) + "┘" + R); };
  // Content row: `c` must be exactly FW visible chars (ANSI codes don't count)
  auto FR = [&](const std::string& c) {
    E("  " + BX + "│" + R + c + BX + "│" + R);
  };

  // Half-pair box (two side-by-side boxes separated by "─ tail-call ──►")
  auto HT = [&]() {
    E("  " + BX + "┌" + dsh(HW) + "┐" + sp(G) + "┌" + dsh(HW) + "┐" + R);
  };
  auto HS = [&]() {  // centre separator with tail-call
    E("  " + BX + "├" + dsh(HW) + "┤" + R + AR + "─ tail-call ──►" + R + BX +
      "├" + dsh(HW) + "┤" + R);
  };
  auto HB = [&]() {
    E("  " + BX + "└" + dsh(HW) + "┘" + sp(G) + "└" + dsh(HW) + "┘" + R);
  };
  // Each of lc / rc must be exactly HW visible chars
  auto HR = [&](const std::string& lc, const std::string& rc) {
    E("  " + BX + "│" + R + lc + BX + "│" + sp(G) + "│" + R + rc + BX + "│" +
      R);
  };

  // Single half-box (left position only)
  auto ST = [&]() { E("  " + BX + "┌" + dsh(HW) + "┐" + R); };
  auto SS = [&]() { E("  " + BX + "├" + dsh(HW) + "┤" + R); };
  auto SB = [&]() { E("  " + BX + "└" + dsh(HW) + "┘" + R); };
  auto SR = [&](const std::string& c) {
    E("  " + BX + "│" + R + c + BX + "│" + R);
  };

  // ── L-shaped connectors ────────────────────────────────────────────────────
  // Arrow characters: │ ┌ ┐ └ ┘ ▼  — each is 1 visual col (multi-byte UTF-8)
  //
  // Label placement: always on the LEFT of the vertical bar, right-aligned to
  // meet it.  Format:  "  <label>   │"  where spaces fill up to col `bar_col`.
  // This leaves the right side of the line clear.
  //
  // Arrow head: the ▼ is placed on the same line that immediately follows the
  // L-corner (no extra │ in between) so the head visually connects to the bend.

  // lbl_line: emit one line with `lbl` left-padded by `indent` spaces,
  // then enough spaces to reach `bar_col`, then the vertical bar │.
  // `indent` lets callers shift the label right without changing bar_col.
  auto lbl_line = [&](const std::string& lbl, int bar_col,
                      int indent = 2) -> std::string {
    if (lbl.empty()) return sp(bar_col) + AR + "│" + R;
    int used = indent + (int) lbl.size();  // visual width before │
    int pad  = bar_col - used;
    return sp(indent) + COND + lbl + R + sp(pad > 0 ? pad : 1) + AR + "│" + R;
  };

  auto connFL = [&](const std::string& lbl = "",
                    int indent             = 2) {  // full → left
    E(lbl_line(lbl, PF, indent));
    E(sp(PL) + AR + "┌" + dsh(PF - PL - 1) + "┘" + R);
    E(sp(PL) + AR + "▼" + R);
  };
  auto connRF = [&](const std::string& lbl = "",
                    int indent             = 2) {  // right → full
    E(lbl_line(lbl, PR, indent));
    E(sp(PF) + AR + "┌" + dsh(PR - PF - 1) + "┘" + R);
    E(sp(PF) + AR + "▼" + R);
  };
  auto connRL = [&](const std::string& lbl = "",
                    int indent             = 2) {  // right → left
    E(lbl_line(lbl, PR, indent));
    E(sp(PL) + AR + "┌" + dsh(PR - PL - 1) + "┘" + R);
    E(sp(PL) + AR + "▼" + R);
  };
  auto connLL = [&](const std::string& lbl = "",
                    int indent             = 2) {  // left → left
    E(lbl_line(lbl, PL, indent));
    E(sp(PL) + AR + "▼" + R);
  };
  auto connLF = [&](const std::string& lbl = "",
                    int indent             = 2) {  // left → full
    E(lbl_line(lbl, PL, indent));
    E(sp(PL) + AR + "└" + dsh(PF - PL - 1) + "┐" + R);
    E(sp(PF) + AR + "▼" + R);
  };
  auto connFF = [&](const std::string& lbl = "",
                    int indent             = 2) {  // full → full
    E(lbl_line(lbl, PF, indent));
    E(sp(PF) + AR + "▼" + R);
  };

  // ── Program half-box content builders  ─────────────────────────────────────
  // Each returns a vector<string> where every string is exactly HW=30 visible
  // chars.  Index 0 = program name, 1 = tag, 2..N = content lines.
  // The separator (├──────┤ / ├tail-call──►├──────┤) is drawn between index 1
  // and index 2 by the caller.
  using Lines = std::vector<std::string>;

  auto mkQER = [&]() -> Lines {
    return {
        " " + QEC + "QERProgram" + R + sp(19),               // 1+10+19 = 30
        "  " + TS2 + "[rule-apply   XDP]" + R + sp(10),      // 2+18+10 = 30
        "  " + ACT + "Gate check (UL/DL open)" + R + sp(5),  // 2+23+5  = 30
        "  " + ACT + "QFI flow classification" + R + sp(5),  // 2+23+5  = 30
    };
  };
  auto mkURR = [&]() -> Lines {
    return {
        " " + URC + "URRProgram" + R + sp(19),
        "  " + TS2 + "[rule-apply   XDP]" + R + sp(10),
        "  " + ACT + "Volume/time accounting" + R + sp(6),  // 2+22+6  = 30
        "  " + ACT + "Threshold/quota check" + R + sp(7),   // 2+21+7  = 30
        "  " + ACT + "Report via ring buffer" + R + sp(6),  // 2+22+6  = 30
    };
  };
  auto mkBAR = [&]() -> Lines {
    return {
        " " + BAC + "BARProgram" + R + sp(19),
        "  " + TS2 + "[rule-apply   XDP]" + R + sp(10),
        "  " + ACT + "DL buffering/DDN suppress" + R + sp(3),  // 2+25+3  = 30
        "  " + ACT + "Buffering state tracking" + R + sp(4),   // 2+24+4  = 30
    };
  };
  auto mkMAR = [&]() -> Lines {
    return {
        " " + MAC + "MARProgram" + R + sp(19),
        "  " + TS2 + "[rule-apply   XDP]" + R + sp(10),
        "  " + ACT + "ATSSS access steering" + R + sp(7),  // 2+21+7  = 30
        "  " + ACT + "Access state 3GPP/Non-3GPP" + R +
            sp(0),  // 2+26+0 = 28 → needs 2 more
        // ↑  "Access state 3GPP/Non-3GPP" = 26 chars → 2+26 = 28, pad = 2
        "  " + RDC + "● XDP_REDIRECT" + R + ACT + " → gNB/DN" + R +
            sp(5),  // 2+1+1+12+9+5 = 30
    };
  };

  // Fix mkMAR row3 padding: "Access state 3GPP/Non-3GPP" = 26 → needs sp(2)
  // (already correct above; the lambda captures by ref so redefine with fix)
  auto mkMAR2 = [&]() -> Lines {
    return {
        " " + MAC + "MARProgram" + R + sp(19),
        "  " + TS2 + "[rule-apply   XDP]" + R + sp(10),
        "  " + ACT + "ATSSS access steering" + R + sp(7),
        "  " + ACT + "Access state (3GPP/Non-3GPP)" + R +
            sp(0),  // 2+28=30 exactly
        "  " + RDC + "● XDP_REDIRECT" + R + ACT + " → gNB/DN" + R + sp(5),
    };
  };

  // ── Render a single or paired half-box ─────────────────────────────────────
  auto drawPair = [&](const Lines& L, const Lines& Rlines) {
    // Pad to same length (both have header[0], tag[1], then content)
    Lines lp = L, rp = Rlines;
    const std::string empty = sp(HW);
    while (lp.size() < rp.size()) lp.push_back(empty);
    while (rp.size() < lp.size()) rp.push_back(empty);
    HT();
    HR(lp[0], rp[0]);  // program names
    HR(lp[1], rp[1]);  // tags
    HS();              // ├──tail-call──►├
    for (size_t i = 2; i < lp.size(); i++) HR(lp[i], rp[i]);
    HB();
  };

  auto drawSingle = [&](const Lines& L) {
    ST();
    SR(L[0]);
    SR(L[1]);
    SS();
    for (size_t i = 2; i < L.size(); i++) SR(L[i]);
    SB();
  };

  // ── Build enabled list ─────────────────────────────────────────────────────
  // Order matches tail-call slots: QER(4) URR(5) BAR(6) MAR(7)
  struct Prog {
    std::string name;
    Lines (*mk)(void*);
    void* ctx;
  };
  std::vector<std::string> enabled;
  if (flags.enable_qer) enabled.push_back("QER");
  if (flags.enable_urr) enabled.push_back("URR");
  if (flags.enable_bar) enabled.push_back("BAR");
  if (flags.enable_mar) enabled.push_back("MAR");

  // Map name → Lines builder
  auto getLines = [&](const std::string& name) -> Lines {
    if (name == "QER") return mkQER();
    if (name == "URR") return mkURR();
    if (name == "BAR") return mkBAR();
    return mkMAR2();
  };

  // Build pairs
  struct Pair {
    std::string L, R;
  };  // R = "" for single
  std::vector<Pair> pairs;
  for (size_t i = 0; i < enabled.size(); i += 2) {
    Pair p;
    p.L = enabled[i];
    p.R = (i + 1 < enabled.size()) ? enabled[i + 1] : "";
    pairs.push_back(p);
  }

  // Build condition label
  auto cond_label = [&](const std::vector<std::string>& progs) -> std::string {
    if (progs.empty()) return "";
    std::string s = "[";
    for (size_t i = 0; i < progs.size(); i++) {
      if (i) s += " + ";
      s += progs[i];
    }
    s += " enabled]";
    return s;
  };

  // ── Render ─────────────────────────────────────────────────────────────────

  E("");
  // "OnNewPacket ●" = 13 chars; centre it over PF=41: start at PF - floor(13/2)
  // = 35
  E(sp(PF - 6) + N3C + "OnNewPacket ●" + R);
  E(sp(PF) + AR + "│" + R);
  E(sp(PF) + AR + "▼" + R);

  // ─── Entry box (always full-width)
  const char* n3name = eth ? "N3EthEntryProgram" : "N3EntryProgram";
  const char* n6name = eth ? "N6EthEntryProgram" : "N6EntryProgram";
  // Row:  " N3EntryProgram  (GTP-U → DN)             [entry-point  XDP] "
  //        1+14+2+12+29+18+1 = 77
  FT();
  FR(" " + N3C + n3name + R + "  " + ACT + "(GTP-U → DN)" + R + sp(29) + TE +
     "[entry-point  XDP]" + R + " ");
  FR(" " + N6C + n6name + R + "  " + ACT + "(DN → GTP-U)" + R + sp(29) + TE +
     "[entry-point  XDP]" + R + " ");
  FS();
  FR("  " + ACT + "Parse direction (GTP-U / UDP)" + R + sp(46));
  FR("  " + ACT + "Session lookup (TEID / UE-IP)" + R + "  " + MAP +
     "◄──── [session_by_ue_ip_map]" + R + sp(16));
  FB();

  // Entry → SessionLookup  (F → L)
  connFL();

  // ─── SessionLookup + PdrMatch (always present, always a pair)
  // SL: ` SessionLookupIPProgram` = 23 → pad 7;  tag 20 → pad 10
  //     `  Get SEID + PDR list`   = 21 → pad 9;  `  Get rules enabled flags` =
  //     25 → pad 5
  // PDR: ` PdrMatchProgram`       = 16 → pad 14; tag 20 → pad 10
  //      `  Match PDR (TEID/UE-IP/SDF)` = 28 → pad 2; `  Get matched 3GPP
  //      rules` = 24 → pad 6
  const std::string sl_tag  = "  " + TS2 + "[session-lkp  XDP]" + R + sp(10);
  const std::string pdr_tag = "  " + TP + "[rule-match   XDP]" + R + sp(10);
  Lines sl_lines            = {
      " " + SLC + (eth ? "SessionLookupETHProgram" : "SessionLookupIPProgram") +
          R + sp(eth ? 5 : 7),
      sl_tag,
      "  " + ACT + "Get SEID + PDR list" + R + sp(9),
      "  " + ACT + "Get rules enabled flags" + R + sp(5),
  };
  Lines pdr_lines = {
      " " + PDC + "PdrMatchProgram" + R + sp(14),
      pdr_tag,
      "  " + ACT + "Match PDR (TEID/UE-IP/SDF)" + R + sp(2),
      "  " + ACT + "Get matched 3GPP rules" + R + sp(6),
  };
  drawPair(sl_lines, pdr_lines);

  // PDR (right) → FAR (full)  (R → F)
  connRF();

  // ─── FAR (always present, full-width)
  // Header: " FARProgram" (11) + sp(47) + "[rule-apply   XDP] " (19) = 77
  FT();
  FR(" " + FAC + "FARProgram" + R + sp(47) + TP + "[rule-apply   XDP]" + R +
     " ");
  FS();
  FR("  " + ACT + "FAR action (FORW / BUFF / DROP)" + R + sp(44));
  // Align ◄ at visual col 33 from content start (positions 29+4=33)
  FR("  " + ACT + "GTP-U outer header creation" + R + "    " + MAP +
     "◄──── [upf_interface_map]" + R + sp(19));
  FR("  " + ACT + "L2 rewrite (ARP resolution)" + R + "    " + MAP +
     "◄──── [arp_table_map]" + R + sp(23));
  FR("  " + ACT + "Redirect to N3/N6" + R + sp(14) + MAP +
     "◄──── [redirect_interfaces_map]" + R + sp(13));
  FB();

  // If no optional rules — done
  if (enabled.empty()) {
    E(sp(PF) + AR + "│" + R + "  " + COND +
      "[no optional rules — FAR is terminal]" + R);
    E("");
    return;
  }

  // FAR → first optional  (F → L), condition shows all enabled progs
  connFL(cond_label(enabled));

  // ─── Optional rule pairs
  for (size_t pi = 0; pi < pairs.size(); pi++) {
    const auto& p      = pairs[pi];
    const bool isLast  = (pi == pairs.size() - 1);
    const bool hasPair = !p.R.empty();

    if (hasPair) {
      drawPair(getLines(p.L), getLines(p.R));
    } else {
      drawSingle(getLines(p.L));
    }

    if (!isLast) {
      // Connector to next pair — exit from right if hasPair, else from left
      // Next row always enters at left
      if (hasPair)
        connRL();
      else
        connLL();
    }
  }

  // ─── QERTC (only if QER enabled, comes after all optional XDP stages)
  if (flags.enable_qer) {
    const auto& lastPair   = pairs.back();
    const bool lastHasPair = !lastPair.R.empty();
    if (lastHasPair)
      connRF("[QER-TC: TC egress, downlink only]", 14);
    else
      connLF("[QER-TC: TC egress, downlink only]", 14);

    // QERTC box  (full-width)
    // Header: " QERTCProgram" (13) + sp(45) + "[qos-enforce   TC] " (19) = 77
    FT();
    FR(" " + TCC + "QERTCProgram" + R + sp(45) + TT + "[qos-enforce   TC]" + R +
       " ");
    FS();
    FR("  " + ACT + "HTB: per-session MBR/GBR per QFI" + R + sp(43));
    FR("  " + ACT + "TC classifier redirect" + R + sp(9) + MAP +
       "◄──── [egress_ifindex_map]" + R + sp(18));
    FR("  " + RDC + "● XDP_REDIRECT" + R + ACT + " → N3 (GTP-U encap) → gNB" +
       R + sp(36));
    FB();
  }

  E("");
}

//------------------------------------------------------------------------------
void DisplayReadyMessage() {
  sleep(5);
  Logger::upf_app().startup(
      "======================================================================"
      "========");

  Logger::upf_app().startup(
      "                   UPF DATA-PATH INITIALIZATION COMPLETE - READY");
  Logger::upf_app().startup(
      "         Waiting for PFCP Session Establishment requests on N4...");
  Logger::upf_app().startup(
      "======================================================================"
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
    if (desc.empty()) desc = "Default QoS Flow";
    if (desc.length() > 50) desc = desc.substr(0, 47) + "...";
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
