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
#include <netlink/route/link.h>
#include <netlink/route/qdisc/htb.h>
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

#ifndef UDP_INTERFACE
#define UDP_INTERFACE UserPlaneComponent::getInstance().getUDPInterface()
#endif  // UDP_INTERFACE

#ifndef GTP_INTERFACE
#define GTP_INTERFACE UserPlaneComponent::getInstance().getGTPInterface()
#endif  // GTP_INTERFACE

#ifndef DEFAULT_RATE
#define DEFAULT_RATE NicInformationGetter::retrieveRate(GTP_INTERFACE)
#ifndef MAX_RATE
#define MAX_RATE DEFAULT_RATE
#endif  // MAX_RATE
#endif  // DEFAULT_RATE

#ifndef DEFAULT_CEIL
#define DEFAULT_CEIL NicInformationGetter::retrieveCeil(GTP_INTERFACE)
#ifndef MAX_CEIL
#define MAX_CEIL DEFAULT_CEIL
#endif  // MAX_CEIL
#endif  // DEFAULT_CEIL

#ifndef BUILD_DIRECTORY
#define BUILD_DIRECTORY                                                        \
  "build/upf/build/upf_app/bpf/CMakeFiles/qer_tc.dir/rules/qer"
#endif  // BUILD_DIRECTORY

static int verbose = 1;

#define EGRESS_HANDLE 0x1
#define EGRESS_PRIORITY 0xC02F

#define INGRESS_HANDLE 0x1
#define INGRESS_PRIORITY 0xC02F

/*---------------------------------------------------------------------------------------------------------------*/
QERProgram::QERProgram() : BPFProgram() {
  mpLifeCycle = std::make_shared<QERProgramLifeCycle>(
      qer_tc_kernel_c__open, qer_tc_kernel_c__load, qer_tc_kernel_c__attach,
      qer_tc_kernel_c__destroy);
}

/*---------------------------------------------------------------------------------------------------------------*/
QERProgram::~QERProgram() {}

/*---------------------------------------------------------------------------------------------------------------*/
void QERProgram::storeQosFlow(std::shared_ptr<pfcp::pfcp_qer> pQer) {
  struct s_fiveQosFlow fiveFlow;
  memset(&fiveFlow, 0, sizeof(struct s_fiveQosFlow));

  fiveFlow.gate = pQer->gate_status.second.dl_gate;
  fiveFlow.gbr  = pQer->gbr.second.dl_gbr;
  fiveFlow.mbr  = pQer->mbr.second.dl_mbr;
  fiveFlow.qfi  = pQer->qfi.second.qfi;

  qosFlowsQfis.push_back(fiveFlow);

  uint32_t qer_id = pQer->qer_id.second.qer_id;

  getQoSFlowMap()->update(qer_id, fiveFlow, BPF_ANY);
}

/*---------------------------------------------------------------------------------------------------------------*/
bool QERProgram::no_htb_root_qdisc(std::string interface) {
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
void QERProgram::setup(
    uint64_t seid, std::vector<std::shared_ptr<pfcp::pfcp_qer>> pQer) {
  spSkeleton = mpLifeCycle->open();
  initializeMaps();
  mpLifeCycle->load();
  mpLifeCycle->attach();

  std::shared_ptr<pfcp::pfcp_qer> default_qer = nullptr;

  std::string cmd = {};
  int rc          = 0;
  int if_index    = 0;

  uint32_t udpInterfaceIndex = if_nametoindex(UDP_INTERFACE.c_str());
  uint32_t gtpInterfaceIndex = if_nametoindex(GTP_INTERFACE.c_str());

  if (udpInterfaceIndex == 0 || gtpInterfaceIndex == 0) {
    Logger::upf_app().error("Failed to retrieve interface indices");
    throw std::runtime_error("Invalid network interface index");
  }

  uint32_t uplinkId   = static_cast<uint32_t>(FlowDirection::UPLINK);
  uint32_t downlinkId = static_cast<uint32_t>(FlowDirection::DOWNLINK);

  mpEgressIfindexMap->update(uplinkId, udpInterfaceIndex, BPF_ANY);
  mpEgressIfindexMap->update(downlinkId, gtpInterfaceIndex, BPF_ANY);

  if (!pQer.empty()) {
    default_qer = retrive_default_qer_with_default_qfi(pQer);

    if (!default_qer) {
      Logger::upf_app().error(
          "QER with default QFI not found! select the first element as "
          "default");
      default_qer = pQer.front();
    }

    // Configure Root Qdisc if not already present
    if (no_htb_root_qdisc(GTP_INTERFACE)) {
      Logger::upf_app().info(
          "Create Root qdisc on interface %s", GTP_INTERFACE.c_str());
      cmd = fmt::format(
          "tc qdisc add dev {} root handle 1:0 htb default {}", GTP_INTERFACE,
          static_cast<uint8_t>(default_qer->qfi.second.qfi));
      // rc = system((const char*) cmd.c_str());
      if (system(cmd.c_str()) != 0) {
        Logger::upf_app().error("Failed to create root Qdisc");
      }
    }

    // Create PDU Session Class
    Logger::upf_app().info("Create PDU Session Class 1:%d", seid);
    cmd = fmt::format(
        "tc class add dev {} parent 1:0 classid 1:{} htb rate {}kbit",
        GTP_INTERFACE, seid, MAX_RATE);

    if (system(cmd.c_str()) != 0) {
      Logger::upf_app().error("Failed to create PDU Session class");
    }

    Logger::upf_app().debug("QDISC Root DL Rate (GBR) : %dkbps", MAX_RATE);
    Logger::upf_app().debug("QDISC Root DL Ceil (MBR) : %dkbps", MAX_CEIL);

    // Process each QER
    for (const auto& qer : pQer) {
      if (qer == default_qer) {
        continue;
      }

      if ((qer->gbr.first) && (qer->mbr.first)) {
        uint32_t qer_id  = qer->qer_id.second.qer_id;
        uint8_t qfi      = qer->qfi.second.qfi;
        uint64_t dl_rate = qer->gbr.second.dl_gbr ? qer->gbr.second.dl_gbr : 1;
        uint64_t dl_ceil = qer->mbr.second.dl_mbr ? qer->mbr.second.dl_mbr : 1;
        uint8_t dl_gate  = qer->gate_status.second.dl_gate;

        Logger::upf_app().warn(
            "Setting dl_rate and dl_ceil to minimum values (1 kbit) for QER %d "
            "if GBR/MBR are null",
            qer_id);

        // Update QoS flow map
        struct s_fiveQosFlow fiveFlow = {};
        fiveFlow.gate                 = dl_gate;
        fiveFlow.gbr                  = dl_rate;
        fiveFlow.mbr                  = dl_ceil;

        getQoSFlowMap()->update(qer_id, fiveFlow, BPF_ANY);

        // Add tc class for QER
        uint16_t minor = (ntohs(seid) * 256) + (qfi * 251 % 256);
        cmd            = fmt::format(
            "tc class add dev {} parent 1:{} classid {}:{} htb rate {}kbit "
            "ceil "
            "{}kbit",
            GTP_INTERFACE, seid, seid, minor, dl_rate, dl_ceil);

        if (system(cmd.c_str()) != 0) {
          Logger::upf_app().error("Failed to add tc class for QER {}", qer_id);
        }

        Logger::upf_app().debug(
            "    HTB Class ID (QER) ........... %d", qer_id);
        Logger::upf_app().debug("         Class QFI:      %d", qfi);
        Logger::upf_app().debug("         Class DL Rate:     %dkbps", dl_rate);
        Logger::upf_app().debug("         Class DL Ceil:     %dkbps", dl_ceil);
      }
    }

    Logger::upf_app().info("Attach Section tc_filter_traffic to gtp interface");
    mpLifeCycle->tcAttachEgress("tc_filter_traffic", GTP_INTERFACE.c_str());

    Logger::upf_app().info("Attach Sesction tc_redirect to udp interface");
    mpLifeCycle->tcAttachIngress("tc_redirect_traffic", UDP_INTERFACE.c_str());
  }
}

// change:
//  sudo tc class change dev br0 parent 1:1 classid 1:10 htb rate 1kbit ceil
//  5kbit burst 16b

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
std::shared_ptr<BPFMap> QERProgram::getQoSFlowMap() const {
  return mpQoSFlowMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> QERProgram::getEgressIfindexMap() const {
  return mpEgressIfindexMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> QERProgram::getSdfFilterMap() const {
  return mpSdfFilterMap;
}
/*---------------------------------------------------------------------------------------------------------------*/
void QERProgram::initializeMaps() {
  // Store all maps available in the program.
  mpMaps = std::make_shared<BPFMaps>(mpLifeCycle->getBPFSkeleton()->skeleton);

  // Warning - The name of the map must be the same of the BPF program.
  mpQoSFlowMap   = std::make_shared<BPFMap>(mpMaps->getMap("m_qos_flow"));
  mpSdfFilterMap = std::make_shared<BPFMap>(mpMaps->getMap("m_sdf_filter"));
  mpEgressIfindexMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_egress_ifindex"));
}
