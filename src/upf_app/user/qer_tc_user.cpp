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

using namespace oai::utils::bpf;
using namespace oai::utils::net;

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
      skel->maps.m_egress_ifindex, "m_egress_ifindex", max_egress_interfaces);

  if (!ok) {
    Logger::upf_app().error(
        "m_egress_ifindex BPF map configuration failed for QER Program");
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
      r2q_root_(40) {
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
      Logger::upf_app().debug(
          "Default QoS Flow: (QER ID, QFI): (%d, %d)",
          qer->qer_id.second.qer_id, qer->qos_flow_id.second.qfi);
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
  Logger::upf_app().debug("Running command: %s", cmd.c_str());
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

  std::shared_ptr<pfcp::pfcp_qer> default_qer =
      RetrieveDefaultQerWithDefaultQfi(qers);

  std::string cmd;
  int rc;

  Logger::upf_app().info("UDP_INTERFACE = %s", udp_iface.c_str());
  Logger::upf_app().info("GTP_INTERFACE = %s", gtp_iface.c_str());

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
    // Configure Root Qdisc if not already present
    if (NoHtbRootQdisc(gtp_iface)) {
      Logger::upf_app().info(
          "Create Root qdisc on interface %s with Default Class: %d, and r2q: "
          "%d",
          gtp_iface.c_str(), GetDefaultClassHandle(), GetR2qRoot());

      cmd = fmt::format(
          "tc qdisc add dev {} root handle 1:0 htb default {} r2q {}",
          gtp_iface, GetDefaultClassHandle(), GetR2qRoot());

      if (system(cmd.c_str()) != 0) {
        Logger::upf_app().error("Failed command: %s", cmd.c_str());
        return;
      }

      Logger::upf_app().debug("QDISC Root DL Rate (GBR) : %dkbps", max_rate);
      Logger::upf_app().debug("QDISC Root DL Ceil (MBR) : %dkbps", max_ceil);
    } else {
      Logger::upf_app().debug(
          "HTB Root qdisc on interface %s already created", gtp_iface.c_str());
    }

    // Create PDU Session Class
    uint16_t casted_seid = static_cast<uint16_t>(seid);

    Logger::upf_app().info(
        "Create PDU Session Class 1:%d with rate: %d", seid, max_rate);
    cmd = fmt::format(
        "tc class add dev {} parent 1: classid 1:{:x} htb rate {}kbit",
        gtp_iface, casted_seid, max_rate);

    if (system(cmd.c_str()) != 0) {
      Logger::upf_app().error("Failed command: %s", cmd.c_str());
    }

    // Process each QER
    BuildPdrMap(pdrs);

    for (const auto& qer : qers) {
      uint8_t qfi    = qer->qos_flow_id.second.qfi;
      uint16_t minor = generate_minor_id(seid, qfi);

      if (qer == default_qer) {
        uint16_t default_minor = (GetDefaultClassHandle() - minor) % 10000;
        //(ntohs(seid) * 256) + (getDefaultClassHandle() * 251 % 256);

        Logger::upf_app().info(
            "Create Default Class 1:%d Child of Parent 1:%d", default_minor,
            seid);
        Logger::upf_app().info(
            "The Default Class 1:%d is of Rate: %d kbit and Ceil: %d kbit",
            default_minor, GetDefaultClassRate(), GetDefaultClassCeil());

        cmd = fmt::format(
            "tc class add dev {} parent 1:{:x} classid 1:{:x} htb rate {}kbit "
            "ceil {}kbit",
            gtp_iface, casted_seid, default_minor, GetDefaultClassRate(),
            GetDefaultClassCeil());

        if (system(cmd.c_str()) != 0) {
          Logger::upf_app().error("Failed command: %s", cmd.c_str());
        } else {
          Logger::upf_app().info(
              "Create PFIFO default class %d: Child of Parent 1:%d", minor,
              default_minor, seid);
          cmd = fmt::format(
              "tc class add dev {} parent 1:{:x} classid 1:{:x} htb rate "
              "{}kbit ceil {}kbit",
              gtp_iface, default_minor, minor, GetDefaultClassRate(),
              GetDefaultClassCeil());

          if (system(cmd.c_str()) != 0) {
            Logger::upf_app().error("Failed command: %s", cmd.c_str());
          }
        }
        continue;
      }

      if (qer->maximum_bitrate.first) {
        uint32_t qer_id = qer->qer_id.second.qer_id;
        Logger::upf_app().debug(
            "qer->maximum_bitrate.second.dl_mbr = %d",
            qer->maximum_bitrate.second.dl_mbr);
        Logger::upf_app().debug(
            "qer->maximum_bitrate.second.ul_mbr = %d",
            qer->maximum_bitrate.second.ul_mbr);
        uint64_t dl_ceil = std::max(qer->maximum_bitrate.second.dl_mbr, 1UL);
        Logger::upf_app().debug("dl_ceil = %d", dl_ceil);
        uint8_t dl_gate = qer->gate_status.second.dl_gate;

        uint64_t dl_rate = 1;
        if (qer->guaranteed_bitrate.first) {
          dl_rate = std::max(qer->guaranteed_bitrate.second.dl_gbr, 1UL);
          Logger::upf_app().debug("dl_rate = %d", dl_rate);
          Logger::upf_app().debug(
              "qer->guaranteed_bitrate.second.ul_gbr = %d",
              qer->guaranteed_bitrate.second.ul_gbr);
          Logger::upf_app().debug(
              "qer->guaranteed_bitrate.second.dl_gbr = %d",
              qer->guaranteed_bitrate.second.dl_gbr);
        }

        Logger::upf_app().info(
            "Create QoS Flow Class 1:%d for PDU Session Parent 1:%d", minor,
            seid);

        cmd = fmt::format(
            "tc class add dev {} parent 1:{:x} classid 1:{:x} htb rate {}kbit "
            "ceil {}kbit",
            gtp_iface, casted_seid, minor, dl_rate, dl_ceil);

        if (system(cmd.c_str()) != 0) {
          Logger::upf_app().error("Failed command: %s", cmd.c_str());
        }

        Logger::upf_app().debug(
            "    HTB Class ID (QER) ........... %d", qer_id);
        Logger::upf_app().debug("         Class QFI:      %d", qfi);
        Logger::upf_app().debug("         Class DL Rate:     %dkbps", dl_rate);
        Logger::upf_app().debug("         Class DL Ceil:     %dkbps", dl_ceil);
      }
    }

    if (NoTcFilterBpf(gtp_iface)) {
      Logger::upf_app().info(
          "Attach Section tc_filter_traffic to gtp interface");
      cmd = fmt::format(
          "tc filter add dev {} parent 1:0 protocol ip bpf obj "
          "/openair-upf/bin/qer_tc_kern.c.o classid 1: direct-action",
          gtp_iface);
      Logger::upf_app().debug("Running command: %s", cmd.c_str());
      if (system(cmd.c_str()) != 0) {
        Logger::upf_app().error("Failed command: %s", cmd.c_str());
      }
    }

    Logger::upf_app().info("Attach Section tc_redirect to udp interface");
    lifecycle_->tcAttachIngress("tc_redirect_traffic", udp_iface.c_str());
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
      std::make_shared<BPFMap>(maps_->GetMap("m_egress_ifindex"));
}
