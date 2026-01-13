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
 * @file qer_tc_user.cpp
 * @brief Implementation of QER TC-BPF program
 * @author OpenAirInterface
 * @date 2025
 */

#include "qer_tc_user.h"
#include <bpf/bpf.h>
#include <stdexcept>
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "interfaces.h"
#include "logger.hpp"
#include "helpers/GetNicInformation.hpp"
#include "helpers/CmdRunner.hpp"
#include "utils/net_utils.hpp"
#include "utils/bpf_utils.hpp"
#include "UserPlaneComponent.h"
#include "sdf_filter.h"
#include "startup_banner.hpp"
#include "number_utils.hpp"

using namespace oai::utils::bpf;
using namespace oai::utils::net;
using namespace oai::utils;

//------------------------------------------------------------------------------
void QERProgram::ConfigureQerMaps(
    struct qer_tc_kern_c* skel, const upf_config& upf_cfg) {
  if (!skel) {
    Logger::upf_app().error("Null skeleton in ConfigureQerMaps");
    return;
  }

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

  // Compute derived limits
  uint32_t max_egress_interfaces = upf_cfg.max_upf_redirect_interfaces;

  bool ok = ConfigureMapMaxEntries(
      skel->maps.egress_ifindex, "egress_ifindex", max_egress_interfaces);

  if (!ok) {
    Logger::upf_app().error(
        "egress_ifindex BPF map configuration failed for QER Program");
    throw std::runtime_error("QER Program map configuration failed");
  }

  // Configure .rodata constants (if available)
  if (skel->rodata) {
    skel->rodata->MAX_EGRESS_INTERFACES = max_egress_interfaces;
  }
}

//------------------------------------------------------------------------------
QERProgram::QERProgram(const upf_config& upf_cfg)
    : BPFProgram(),
      default_class_handle_(65535),
      default_class_rate_(1024),
      default_class_ceil_(2048),
      r2q_root_(1000) {
  Logger::upf_app().info("Initializing QER TC BPF program...");

  // Define the 'open' lambda for the QER skeleton
  auto open_fn = [&upf_cfg, this]() -> qer_tc_kern_c* {
    struct qer_tc_kern_c* skel = qer_tc_kern_c__open();
    if (!skel) {
      Logger::upf_app().error("Failed to open QER TC BPF skeleton");
      return nullptr;
    }

    // Configure map sizes and .rodata constants
    this->ConfigureQerMaps(skel, upf_cfg);
    return skel;
  };

  // Initialize lifecycle management
  lifecycle_ = std::make_shared<QERProgramLifeCycle>(
      open_fn,
      /* load */ qer_tc_kern_c__load,
      /* attach */ qer_tc_kern_c__attach,
      /* destroy */ qer_tc_kern_c__destroy);
}

//------------------------------------------------------------------------------
QERProgram::~QERProgram() {}

//------------------------------------------------------------------------------
bool QERProgram::NoHtbRootQdisc(const std::string& interface) {
  std::string cmd = fmt::format(
      "tc qdisc show dev {} | awk '/htb/ {{found=1; print 1}} END {{if "
      "(!found) print 0}}'",
      interface);
  uint32_t ret = std::stoi(CmdRunner::exec(cmd).c_str());
  return ret ? false : true;
}

//------------------------------------------------------------------------------
bool QERProgram::NoHtbDefaultClass(const std::string& interface) {
  std::string cmd = fmt::format(
      "tc qdisc show dev {} | awk '/htb/ && /default/ {{found=1; print 1}} "
      "END {{if (!found) print 0}}'",
      interface);
  uint32_t ret = std::stoi(CmdRunner::exec(cmd).c_str());
  return ret ? false : true;
}

//------------------------------------------------------------------------------
std::shared_ptr<pfcp::pfcp_qer> QERProgram::RetrieveDefaultQerWithDefaultQfi(
    std::vector<std::shared_ptr<pfcp::pfcp_qer>> qers) {
  for (const auto& qer : qers) {
    if (!qer->guaranteed_bitrate.first && !qer->maximum_bitrate.first) {
      return qer;
    }
  }
  return nullptr;
}

//------------------------------------------------------------------------------
void QERProgram::BuildPdrMap(
    const std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs) {
  pdr_map_.clear();
  for (const auto& pdr : pdrs) {
    if (pdr && pdr->qer_id.first) {
      pdr_map_[pdr->qer_id.second.qer_id] = pdr;
    }
  }
}

//------------------------------------------------------------------------------
std::shared_ptr<pfcp::pfcp_pdr> QERProgram::GetPdrByQerId(
    uint32_t qer_id) const {
  auto it = pdr_map_.find(qer_id);
  return (it != pdr_map_.end()) ? it->second : nullptr;
}

//------------------------------------------------------------------------------
bool QERProgram::NoTcFilterBpf(const std::string& interface) {
  std::string cmd = fmt::format(
      "tc filter show dev {} | awk '/bpf/ {{found=1; print 1}} END {{if "
      "(!found) print 0}}'",
      interface);
  uint32_t ret = std::stoi(CmdRunner::exec(cmd).c_str());
  return ret ? false : true;
}

//------------------------------------------------------------------------------
void QERProgram::Setup(
    uint64_t seid, std::vector<std::shared_ptr<pfcp::pfcp_qer>> qers,
    std::vector<std::shared_ptr<pfcp::pfcp_pdr>> pdrs) {
  const std::string udp_iface =
      UserPlaneComponent::GetInstance().GetUDPInterface();
  const std::string gtp_iface =
      UserPlaneComponent::GetInstance().GetGTPInterface();

  const uint32_t default_rate = NicInformationGetter::retrieveRate(gtp_iface);
  const uint32_t max_rate     = default_rate;
  const uint32_t default_ceil = NicInformationGetter::retrieveCeil(gtp_iface);
  const uint32_t max_ceil     = default_ceil;

  skeleton_ = lifecycle_->open();
  InitializeMaps();
  lifecycle_->load();
  lifecycle_->attach();

  std::string cmd;

  uint32_t udp_interface_index = if_nametoindex(udp_iface.c_str());
  uint32_t gtp_interface_index = if_nametoindex(gtp_iface.c_str());

  if (udp_interface_index == 0 || gtp_interface_index == 0) {
    Logger::upf_app().error("Failed to retrieve interface indices");
    throw std::runtime_error("Invalid network interface index");
  }

  uint32_t uplink_id   = static_cast<uint32_t>(FlowDirection::UPLINK);
  uint32_t downlink_id = static_cast<uint32_t>(FlowDirection::DOWNLINK);

  egress_ifindex_map_->Update(uplink_id, udp_interface_index, BPF_ANY);
  egress_ifindex_map_->Update(downlink_id, gtp_interface_index, BPF_ANY);

  if (!qers.empty()) {
    // Start QoS Setup Banner
    LogQosSetupStart(seid, gtp_iface);

    Logger::upf_app().info(
        "  ┌─ N6 Interface (Non-GTP): %s", udp_iface.c_str());
    Logger::upf_app().info(
        "  └─ N3 Interface (GTP):     %s", gtp_iface.c_str());

    std::shared_ptr<pfcp::pfcp_qer> default_qer =
        RetrieveDefaultQerWithDefaultQfi(qers);

    if (default_qer) {
      Logger::upf_app().debug(
          "  → Default QoS Flow detected: QER=%u, QFI=%u",
          default_qer->qer_id.second.qer_id,
          default_qer->qos_flow_id.second.qfi);
    }

    std::vector<QosFlowInfo> qos_flows;
    bool has_errors = false;

    // Configure Root Qdisc if not already present
    if (NoHtbRootQdisc(gtp_iface)) {
      Logger::upf_app().info(
          "  ┌─ Creating Root HTB Qdisc on %s", gtp_iface.c_str());
      Logger::upf_app().info(
          "  │  • Default Class: %u", GetDefaultClassHandle());
      Logger::upf_app().info("  │  • r2q Parameter: %u", GetR2qRoot());
      Logger::upf_app().debug(
          " │  • Max DL Rate:   %s kbps", FormatNumber(max_rate).c_str());
      Logger::upf_app().debug(
          " │  • Max DL Ceil:   %s kbps", FormatNumber(max_ceil).c_str());

      cmd = fmt::format(
          "tc qdisc add dev {} root handle 1:0 htb default {} r2q {}",
          gtp_iface, GetDefaultClassHandle(), GetR2qRoot());

      if (system(cmd.c_str()) != 0) {
        Logger::upf_app().error(
            "  └─ ✗ Failed to create root qdisc %s on %s", cmd.c_str(),
            gtp_iface.c_str());
        has_errors = true;
      } else {
        Logger::upf_app().info(
            "  └─ ✓ Root qdisc created successfully on interface: %s",
            gtp_iface.c_str());
      }
    } else {
      Logger::upf_app().debug(
          "HTB Root qdisc on interface: %s, already created",
          gtp_iface.c_str());
    }

    // Create PDU Session Class
    uint16_t casted_seid = static_cast<uint16_t>(seid);
    uint64_t rate_bytes  = ((uint64_t) max_rate * 1000) / 8;
    uint32_t pdu_quantum = rate_bytes / GetR2qRoot();

    Logger::upf_app().info("  ┌─ Creating PDU Session Class 1:%x", casted_seid);
    Logger::upf_app().info(
        "  │  • Session Rate: %s kbps", FormatNumber(max_rate).c_str());
    cmd = fmt::format(
        "tc class add dev {} parent 1: classid 1:{:x} htb rate {}kbit quantum "
        "{}",
        gtp_iface, casted_seid, max_rate, pdu_quantum);

    if (system(cmd.c_str()) != 0) {
      Logger::upf_app().error(
          "  └─ ✗ Failed to create PDU session class 1:%x", casted_seid);
      has_errors = true;
    } else {
      Logger::upf_app().info(
          "  └─ ✓ PDU session class  1:%x created successfully", casted_seid);
    }

    // Process each QER
    BuildPdrMap(pdrs);

    for (const auto& qer : qers) {
      uint8_t qfi    = qer->qos_flow_id.second.qfi;
      uint16_t minor = generate_minor_id(seid, qfi);
      // Handle default QER
      if (qer == default_qer) {
        uint16_t default_minor = (GetDefaultClassHandle() - minor) % 10000;
        //(ntohs(seid) * 256) + (getDefaultClassHandle() * 251 % 256);

        Logger::upf_app().info(
            "  ┌─ Creating Default Class 1:%d Child of Parent 1:%d",
            default_minor, seid);

        Logger::upf_app().debug(
            " │  • Rate:   %s kbps",
            FormatNumber(GetDefaultClassRate()).c_str());
        Logger::upf_app().debug(
            " │  • Ceil:   %s kbps",
            FormatNumber(GetDefaultClassCeil()).c_str());

        uint64_t default_rate_bytes =
            ((uint64_t) GetDefaultClassRate() * 1000) / 8;
        uint32_t default_quantum = default_rate_bytes / GetR2qRoot();
        cmd                      = fmt::format(
            "tc class add dev {} parent 1:{:x} classid 1:{:x} htb rate {}kbit "
            "ceil {}kbit quantum {}",
            gtp_iface, casted_seid, default_minor, GetDefaultClassRate(),
            GetDefaultClassCeil(), default_quantum);

        if (system(cmd.c_str()) != 0) {
          Logger::upf_app().error(
              "  └─ ✗ Failed to create default class 1:%x", default_minor);
          has_errors = true;
        } else {
          Logger::upf_app().info(
              "  └─ ✓ Default class  1:%x created successfully", default_minor);

          Logger::upf_app().info(
              "  ┌─ Creating PFIFO default class %d: Child of Parent 1:%d",
              minor, default_minor, seid);
          cmd = fmt::format(
              "tc class add dev {} parent 1:{:x} classid 1:{:x} htb rate "
              "{}kbit ceil {}kbit quantum {}",
              gtp_iface, default_minor, minor, GetDefaultClassRate(),
              GetDefaultClassCeil(), default_quantum);

          /*
          cmd = fmt::format(
           "tc qdisc add dev {} parent 1:{:x} handle {:x}: pfifo", gtp_iface,
           default_minor, minor);
          */

          if (system(cmd.c_str()) != 0) {
            Logger::upf_app().error(
                "  └─ ✗ Failed to create PFIFO for default class");
            has_errors = true;
          } else {
            Logger::upf_app().info(
                "  └─ ✓ PFIFO default class  1:%d created successfully", minor);
          }

          // Add default flow to table
          QosFlowInfo flow;
          flow.qer_id           = qer->qer_id.second.qer_id;
          flow.qfi              = qfi;
          flow.rate_kbps        = GetDefaultClassRate();
          flow.ceil_kbps        = GetDefaultClassCeil();
          flow.class_id         = default_minor;
          flow.flow_description = "Default QoS Flow";
          qos_flows.push_back(flow);
        }
        continue;
      }

      // Handle GBR/MBR QERs
      if (qer->maximum_bitrate.first) {
        uint32_t qer_id  = qer->qer_id.second.qer_id;
        uint64_t dl_ceil = std::max(qer->maximum_bitrate.second.dl_mbr, 1UL);
        uint8_t dl_gate  = qer->gate_status.second.dl_gate;

        uint64_t dl_rate = 1;

        if (qer->guaranteed_bitrate.first) {
          // GBR present: use the SMF-provided GBR value
          dl_rate = std::max(qer->guaranteed_bitrate.second.dl_gbr, 1UL);
        } else {
          // GBR absent: fallback to 80% of MBR
          dl_rate = std::max(static_cast<unsigned long>(dl_ceil * 0.8), 1UL);
          Logger::upf_app().warn("QoS Flow missing GBR: set it to 0.8 x MBR");
        }

        Logger::upf_app().info(
            "  ┌─ Createing QoS Flow Class 1:%d for PDU Session Parent 1:%d",
            minor, seid);
        Logger::upf_app().info(
            "  │  • QoS Flow Rate (GBR): %s kbps",
            FormatNumber(dl_rate).c_str());
        Logger::upf_app().info(
            "  │  • QoS Flow Ceil (MBR): %s kbps",
            FormatNumber(dl_ceil).c_str());

        cmd = fmt::format(
            "tc class add dev {} parent 1:{:x} classid 1:{:x} htb rate {}kbit "
            "ceil {}kbit",
            gtp_iface, casted_seid, minor, dl_rate, dl_ceil);

        if (system(cmd.c_str()) != 0) {
          Logger::upf_app().error(
              "  └─ ✗ Failed to create QoS flow class for QER %u", qer_id);
          has_errors = true;
        } else {
          // Add flow to table
          QosFlowInfo flow;
          flow.qer_id    = qer_id;
          flow.qfi       = qfi;
          flow.rate_kbps = dl_rate;
          flow.ceil_kbps = dl_ceil;
          flow.class_id  = minor;

          // Get flow description from associated PDR
          auto pdr = GetPdrByQerId(qer_id);
          if (pdr) {
            pfcp::pdi pdi;
            if (pdr->get(pdi)) {
              pfcp::sdf_filter_t sdf;
              if (pdi.get(sdf) && sdf.fd &&
                  sdf.length_of_flow_description > 0) {
                flow.flow_description = sdf.flow_description;
              }
            }
          }
          if (flow.flow_description.empty()) {
            flow.flow_description = "permit out ip from any to any";
          }

          qos_flows.push_back(flow);
          Logger::upf_app().info(
              "  └─ ✓ QoS Flow class  1:%d created successfully for QER %u",
              minor, qer_id);
        }
      }
    }

    // Attach TC BPF filter (silent)
    if (NoTcFilterBpf(gtp_iface)) {
      Logger::upf_app().info(
          "Attach Section tc_filter_traffic to gtp interface");
      cmd = fmt::format(
          "tc filter add dev {} parent 1:0 protocol ip bpf obj "
          "/openair-upf/bin/qer_tc_kern.c.o classid 1: direct-action",
          gtp_iface.c_str());
      if (system(cmd.c_str()) != 0) {
        Logger::upf_app().error("Failed to attach TC BPF filter");
        has_errors = true;
      }
    }

    // Attach TC redirect to UDP interface
    Logger::upf_app().info("Attach Section tc_redirect to udp interface");
    lifecycle_->tcAttachIngress("tc_redirect_traffic", udp_iface.c_str());

    // Display QoS Flow Table
    if (!qos_flows.empty()) {
      DisplayQosFlowTable(seid, qos_flows);
    }

    // End QoS Setup Banner
    LogQosSetupComplete(seid, qos_flows.size(), has_errors);
  }
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMaps> QERProgram::GetMaps() {
  return maps_;
}

//------------------------------------------------------------------------------
void QERProgram::TearDown() {
  lifecycle_->tearDown();
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> QERProgram::Get5GQoSFlowParamsMap() const {
  return qos_flow_params_map_;
}

//------------------------------------------------------------------------------
std::shared_ptr<BPFMap> QERProgram::GetEgressIfindexMap() const {
  return egress_ifindex_map_;
}

//------------------------------------------------------------------------------
void QERProgram::InitializeMaps() {
  // Store all maps available in the program
  maps_ = std::make_shared<BPFMaps>(lifecycle_->getBPFSkeleton()->skeleton);

  egress_ifindex_map_ =
      std::make_shared<BPFMap>(maps_->GetMap("egress_ifindex"));
}
