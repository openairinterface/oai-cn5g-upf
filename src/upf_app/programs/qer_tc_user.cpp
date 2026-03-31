/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "qer_tc_user.h"
#include <SessionManager.h>
#include <bpf/bpf.h>  // bpf calls
#include <iostream>   // cout
#include <stdexcept>  // exception
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include <chrono>
#include <iostream>
#include "interfaces.h"
#include "logger.hpp"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "helpers/GetNicInformation.hpp"
#include "helpers/CmdRunner.hpp"

#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <net/if.h>

#include <getopt.h>
#include <linux/in6.h>
#include <arpa/inet.h>
#include <linux/bpf.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "sdf_filter.h"

#include "utils/net_utils.hpp"
#include "utils/bpf_utils.hpp"

using namespace oai::utils::bpf;
using namespace oai::utils::net;

static int verbose = 1;

/*---------------------------------------------------------------------------------------------------------------*/
void QERProgram::configureQerMaps(
    struct qer_tc_kernel_c* skel, const upf_config& upf_cfg) {
  if (!skel) {
    Logger::upf_app().error(
        "Null skeleton in configure_pfcp_session_lookup_maps");
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

  // Compute derived limits
  uint32_t max_egress_interfaces = upf_cfg.max_upf_redirect_interfaces;

  bool ok = configure_map_max_entries(
      skel->maps.m_egress_ifindex, "m_egress_ifindex", max_egress_interfaces);

  if (!ok) {
    Logger::upf_app().error(
        "m_egress_ifindex BPF map configuration failed for QER Program");
    throw std::runtime_error("QER Program map configuration failed");
  }

  // Configure .rodata constants (if available)
  if (skel->rodata) {
    skel->rodata->max_egress_interfaces = max_egress_interfaces;
  }
}

/*---------------------------------------------------------------------------------------------------------------*/
QERProgram::QERProgram(const upf_config& upf_cfg)
    : BPFProgram(),
      m_default_class_handle(65535),
      m_default_class_rate(1024),
      m_default_class_ceil(2048),
      m_r2q_root(40) {
  struct qer_tc_kernel_c* skel = nullptr;
  int ret                      = -1;

  Logger::upf_app().info("Initializing QER TC BPF program...");

  // Define the 'open' lambda for the QER skeleton
  auto open_fn = [&upf_cfg, this]() -> qer_tc_kernel_c* {
    struct qer_tc_kernel_c* skel = qer_tc_kernel_c__open();
    if (!skel) {
      Logger::upf_app().error("Failed to open QER TC BPF skeleton");
      return nullptr;
    }

    // Configure map sizes and .rodata constants
    this->configureQerMaps(skel, upf_cfg);
    return skel;
  };

  // Initialize lifecycle management
  mpLifeCycle = std::make_shared<QERProgramLifeCycle>(
      open_fn,
      /* load */ qer_tc_kernel_c__load,
      /* attach */ qer_tc_kernel_c__attach,
      /* destroy */ qer_tc_kernel_c__destroy);
}

/*---------------------------------------------------------------------------------------------------------------*/
QERProgram::~QERProgram() {}

/*---------------------------------------------------------------------------------------------------------------*/
bool QERProgram::no_htb_root_qdisc(const std::string interface) {
  std::string cmd = {};
  uint32_t ret    = 0;

  cmd = fmt::format(
      "tc qdisc show dev {} | awk '/htb/ {{found=1; print 1}} END {{if "
      "(!found) print 0}}'",
      interface);
  ret = std::stoi(CmdRunner::exec(cmd).c_str());
  return ret ? false : true;
}

/*---------------------------------------------------------------------------------------------------------------*/
bool QERProgram::no_htb_default_class(const std::string interface) {
  std::string cmd = {};
  uint32_t ret    = 0;

  cmd = fmt::format(
      "tc qdisc show dev {} | awk '/htb/ && /default/ {{found=1; print 1}} END "
      "{{if "
      "(!found) print 0}}'",
      interface);
  ret = std::stoi(CmdRunner::exec(cmd).c_str());
  return ret ? false : true;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<pfcp::pfcp_qer>
QERProgram::retrive_default_qer_with_default_qfi(
    std::vector<std::shared_ptr<pfcp::pfcp_qer>> pQer) {
  for (const auto& qer : pQer) {
    if (!qer->gbr.first && !qer->mbr.first) {
      Logger::upf_app().debug(
          "Default QoS Flow: (QER ID, QFI): (%d, %d)",
          qer->qer_id.second.qer_id, qer->qfi.second.qfi);
      return qer;
    }
  }

  // Return nullptr if no such QER is found
  return nullptr;
}

/*---------------------------------------------------------------------------------------------------------------*/
void QERProgram::build_pdr_map(
    const std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs) {
  pdr_map.clear();
  for (const auto& pdr : pdrs) {
    if (pdr && pdr->qer_id.first) {
      pdr_map[pdr->qer_id.second.qer_id] = pdr;
    }
  }
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<pfcp::pfcp_pdr> QERProgram::get_pdr_by_qer_id(
    uint32_t qer_id) const {
  auto it = pdr_map.find(qer_id);
  return (it != pdr_map.end()) ? it->second : nullptr;
}
bool QERProgram::no_tc_filter_bpf(std::string interface) {
  std::string cmd = {};
  uint32_t ret    = 0;

  cmd = fmt::format(
      "tc filter show dev {} | awk '/bpf/ {{found=1; print 1}} END {{if "
      "(!found) print 0}}'",
      interface.c_str());
  Logger::upf_app().debug("Running command: %s", cmd.c_str());
  ret = std::stoi(CmdRunner::exec(cmd).c_str());
  return ret ? false : true;
}

/*---------------------------------------------------------------------------------------------------------------*/
void QERProgram::setup(
    uint64_t seid, std::vector<std::shared_ptr<pfcp::pfcp_qer>> pQer,
    std::vector<std::shared_ptr<pfcp::pfcp_pdr>> pdrs) {
  const std::string udpIface =
      UserPlaneComponent::getInstance().getUDPInterface();
  const std::string gtpIface =
      UserPlaneComponent::getInstance().getGTPInterface();

  const uint32_t default_rate = NicInformationGetter::retrieveRate(gtpIface);
  const uint32_t max_rate     = default_rate;
  const uint32_t default_ceil = NicInformationGetter::retrieveCeil(gtpIface);
  const uint32_t max_ceil     = default_ceil;

  spSkeleton = mpLifeCycle->open();

  initializeMaps();
  mpLifeCycle->load();
  mpLifeCycle->attach();

  std::shared_ptr<pfcp::pfcp_qer> default_qer =
      retrive_default_qer_with_default_qfi(pQer);

  std::string cmd = {};
  int rc          = 0;
  int if_index    = 0;

  Logger::upf_app().info(
      "UDP_INTERFACE = %s",
      UserPlaneComponent::getInstance().getUDPInterface());
  Logger::upf_app().info("GTP_INTERFACE = %s", gtpIface.c_str());

  uint32_t udpInterfaceIndex = if_nametoindex(udpIface.c_str());
  uint32_t gtpInterfaceIndex = if_nametoindex(gtpIface.c_str());

  if (udpInterfaceIndex == 0 || gtpInterfaceIndex == 0) {
    Logger::upf_app().error("Failed to retrieve interface indices");
    throw std::runtime_error("Invalid network interface index");
  }

  uint32_t uplinkId   = static_cast<uint32_t>(FlowDirection::UPLINK);
  uint32_t downlinkId = static_cast<uint32_t>(FlowDirection::DOWNLINK);

  mpEgressIfindexMap->update(uplinkId, udpInterfaceIndex, BPF_ANY);
  mpEgressIfindexMap->update(downlinkId, gtpInterfaceIndex, BPF_ANY);

  if (!pQer.empty()) {
    // Configure Root Qdisc if not already present
    if (no_htb_root_qdisc(gtpIface)) {
      Logger::upf_app().info(
          "Create Root qdisc on interface %s with Default Class: %d, and r2q: "
          "%d",
          gtpIface.c_str(), getDefaultClassHandle(), getR2qRoot());

      cmd = fmt::format(
          "tc qdisc add dev {} root handle 1:0 htb default {} r2q {}", gtpIface,
          getDefaultClassHandle(), getR2qRoot());

      if (system(cmd.c_str()) != 0) {
        Logger::upf_app().error("Failed command: %s", cmd);
        return;
      }

      Logger::upf_app().debug("QDISC Root DL Rate (GBR) : %dkbps", max_rate);
      Logger::upf_app().debug("QDISC Root DL Ceil (MBR) : %dkbps", max_ceil);
    } else {
      Logger::upf_app().debug(
          "HTB Root qdisc on interface %s already created", gtpIface.c_str());
    }

    // Create PDU Session Class
    uint16_t casted_seid = static_cast<uint16_t>(seid);

    Logger::upf_app().info(
        "Create PDU Session Class 1:%d with rate: %d", seid, max_rate);
    cmd = fmt::format(
        "tc class add dev {} parent 1: classid 1:{:x} htb rate {}kbit",
        gtpIface, casted_seid, max_rate);

    if (system(cmd.c_str()) != 0) {
      Logger::upf_app().error("Failed command: %s", cmd);
    }

    // Process each QER
    build_pdr_map(pdrs);

    for (const auto& qer : pQer) {
      uint8_t qfi    = qer->qfi.second.qfi;
      uint16_t minor = generate_minor_id(seid, qfi);

      if (qer == default_qer) {
        uint16_t default_minor = (getDefaultClassHandle() - minor) % 10000;
        //(ntohs(seid) * 256) + (getDefaultClassHandle() * 251 % 256);

        Logger::upf_app().info(
            "Create Default Class 1:%d Child of Parent 1:%d", default_minor,
            seid);
        Logger::upf_app().info(
            "The Default Class 1:%d is of Rate: %d kbit and Ceil: %d kbit",
            default_minor, getDefaultClassRate(), getDefaultClassCeil());

        cmd = fmt::format(
            "tc class add dev {} parent 1:{:x} classid 1:{:x} htb rate {}kbit "
            "ceil "
            "{}kbit",
            gtpIface, casted_seid, default_minor, getDefaultClassRate(),
            getDefaultClassCeil());

        if (system(cmd.c_str()) != 0) {
          Logger::upf_app().error("Failed command: %s", cmd);
        } else {
          Logger::upf_app().info(
              "Create PFIFO default class %d: Child of Parent 1:%d", minor,
              default_minor, seid);
          cmd = fmt::format(
              "tc class add dev {} parent 1:{:x} classid 1:{:x} htb rate "
              "{}kbit "
              "ceil {}kbit",
              gtpIface, default_minor, minor, getDefaultClassRate(),
              getDefaultClassCeil());

          if (system(cmd.c_str()) != 0) {
            Logger::upf_app().error("Failed command: %s", cmd);
          }
        }
        continue;
      }

      if (qer->mbr.first) {
        uint32_t qer_id = qer->qer_id.second.qer_id;
        Logger::upf_app().debug(
            "qer->mbr.second.dl_mbr = %d", qer->mbr.second.dl_mbr);
        Logger::upf_app().debug(
            "qer->mbr.second.ul_mbr = %d", qer->mbr.second.ul_mbr);
        uint64_t dl_ceil = std::max(qer->mbr.second.dl_mbr, 1UL);
        Logger::upf_app().debug("dl_ceil = %d", dl_ceil);
        uint8_t dl_gate = qer->gate_status.second.dl_gate;

        uint64_t dl_rate = 1;
        if (qer->gbr.first) {
          dl_rate = std::max(qer->gbr.second.dl_gbr, 1UL);
          Logger::upf_app().debug("dl_rate = %d", dl_rate);
          Logger::upf_app().debug(
              "qer->gbr.second.ul_gbr = %d", qer->gbr.second.ul_gbr);
          Logger::upf_app().debug(
              "qer->gbr.second.dl_gbr = %d", qer->gbr.second.dl_gbr);
        }

        Logger::upf_app().info(
            "Create QoS Flow Class 1:%d for PDU Session Parent 1:%d", minor,
            seid);

        cmd = fmt::format(
            "tc class add dev {} parent 1:{:x} classid 1:{:x} htb rate {}kbit "
            "ceil "
            "{}kbit",
            gtpIface, casted_seid, minor, dl_rate, dl_ceil);

        if (system(cmd.c_str()) != 0) {
          Logger::upf_app().error("Failed command: %s", cmd);
        }

        Logger::upf_app().debug(
            "    HTB Class ID (QER) ........... %d", qer_id);
        Logger::upf_app().debug("         Class QFI:      %d", qfi);
        Logger::upf_app().debug("         Class DL Rate:     %dkbps", dl_rate);
        Logger::upf_app().debug("         Class DL Ceil:     %dkbps", dl_ceil);
      }
    }

    if (no_tc_filter_bpf(gtpIface)) {
      Logger::upf_app().info(
          "Attach Section tc_filter_traffic to gtp interface");
      // Create tc filter for the GTP interface
      cmd = fmt::format(
          "tc filter add dev {} parent 1:0 protocol ip bpf obj "
          "/openair-upf/bin/qer_tc_kernel.c.o classid 1: direct-action",
          gtpIface.c_str());
      Logger::upf_app().debug("Running command: %s", cmd.c_str());
      if (system(cmd.c_str()) != 0) {
        Logger::upf_app().error("Failed command: %s", cmd.c_str());
      }
    }

    Logger::upf_app().info("Attach Section tc_redirect to udp interface");
    mpLifeCycle->tcAttachIngress("tc_redirect_traffic", udpIface.c_str());
  }
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMaps> QERProgram::getMaps() {
  return mpMaps;
}

/*---------------------------------------------------------------------------------------------------------------*/
// TODO: Check when kill when running.
// It was noted the infinity loop.
void QERProgram::tearDown() {
  mpLifeCycle->tearDown();
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> QERProgram::get5GQoSFlowParamsMap() const {
  return mp5GQoSFlowParamsMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> QERProgram::getEgressIfindexMap() const {
  return mpEgressIfindexMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
void QERProgram::initializeMaps() {
  // Store all maps available in the program.
  mpMaps = std::make_shared<BPFMaps>(mpLifeCycle->getBPFSkeleton()->skeleton);

  mpEgressIfindexMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_egress_ifindex"));
}
