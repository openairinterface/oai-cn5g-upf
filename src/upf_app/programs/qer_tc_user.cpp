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

#ifndef HTB_SCHEDULER
#define HTB_SCHEDULER "htb"
#endif  // HTB_SCHEDULER

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

#ifndef DEFAULT_QFI
#define DEFAULT_QFI 5
#endif  // DEFAULT_QFI

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

  fiveFlow.gate.dl_gate = pQer->gate_status.second.dl_gate;
  fiveFlow.gate.ul_gate = pQer->gate_status.second.ul_gate;

  fiveFlow.gbr.dl_gbr = pQer->gbr.second.dl_gbr;
  fiveFlow.gbr.ul_gbr = pQer->gbr.second.ul_gbr;

  fiveFlow.mbr.dl_mbr = pQer->mbr.second.dl_mbr;
  fiveFlow.mbr.ul_mbr = pQer->mbr.second.ul_mbr;

  fiveFlow.qfi = pQer->qfi.second.qfi;

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
void QERProgram::setup(
    uint64_t seid, std::vector<std::shared_ptr<pfcp::pfcp_qer>> pQer) {
  spSkeleton = mpLifeCycle->open();
  initializeMaps();
  mpLifeCycle->load();
  mpLifeCycle->attach();

  struct qer_tc_kernel_c* obj = NULL;

  std::string cmd = {};
  int rc          = 0;
  int if_index    = 0;

  uint32_t udpInterfaceIndex = if_nametoindex(UDP_INTERFACE.c_str());
  uint32_t gtpInterfaceIndex = if_nametoindex(GTP_INTERFACE.c_str());
  uint32_t uplinkId          = static_cast<uint32_t>(FlowDirection::UPLINK);
  uint32_t downlinkId        = static_cast<uint32_t>(FlowDirection::DOWNLINK);
  mpEgressIfindexMap->update(uplinkId, udpInterfaceIndex, BPF_ANY);
  mpEgressIfindexMap->update(downlinkId, gtpInterfaceIndex, BPF_ANY);

  if (no_htb_root_qdisc(GTP_INTERFACE)) {
    Logger::upf_app().info(
        "Creating Root qdisc on interface %s", GTP_INTERFACE.c_str());
    cmd = fmt::format(
        "tc qdisc add dev {} root handle 1:0 htb default {}", GTP_INTERFACE,
        DEFAULT_QFI);
    rc = system((const char*) cmd.c_str());
  }

  Logger::upf_app().info("Create PDU Session Class 1:%d", seid);
  cmd = fmt::format(
      "tc class add dev {} parent 1:0 classid 1:{} htb rate {}kbit",
      GTP_INTERFACE, seid, MAX_RATE);
  rc = system((const char*) cmd.c_str());

  Logger::upf_app().debug("QDISC Root DL Rate (GBR) : %dkbps", MAX_RATE);
  Logger::upf_app().debug("QDISC Root DL Ceil (MBR) : %dkbps", MAX_CEIL);

  for (const auto& qer : pQer) {
    if (qer == nullptr) {
      continue;
    }

    uint8_t qfi     = qer->qfi.second.qfi;
    uint32_t qer_id = qer->qer_id.second.qer_id;

    Logger::upf_app().warn(
        "Set dl_rate and dl_ceil to 1kbit, for QER %d, as the minimum required "
        "values to \n"
        "create a tc class within the Linux kernel. These values are only used "
        "if \n"
        " dl_rate and dl_ceil are null within the PFCP Establishment request. "
        "Of course, the \n "
        "class rate and ceil are updated from the PFCP Modification request",
        qer_id);
    uint64_t dl_rate = 1;
    uint64_t dl_ceil = 1;
    uint64_t ul_rate = 1;
    uint64_t ul_ceil = 1;
    uint8_t dl_gate  = 0;
    uint8_t ul_gate  = 0;

    if (qfi != DEFAULT_QFI) {
      if (qer->gbr.second.dl_gbr != 0) dl_rate = qer->gbr.second.dl_gbr;

      if (qer->gbr.second.ul_gbr != 0) ul_rate = qer->gbr.second.ul_gbr;

      if (qer->mbr.second.dl_mbr != 0) dl_ceil = qer->mbr.second.dl_mbr;

      if (qer->mbr.second.ul_mbr != 0) ul_ceil = qer->mbr.second.ul_mbr;

      dl_gate = qer->gate_status.second.dl_gate;
      ul_gate = qer->gate_status.second.ul_gate;
    }

    struct s_fiveQosFlow fiveFlow;
    memset(&fiveFlow, 0, sizeof(struct s_fiveQosFlow));

    fiveFlow.gate.dl_gate = dl_gate;
    fiveFlow.gate.ul_gate = ul_gate;
    fiveFlow.gbr.dl_gbr   = dl_rate;
    fiveFlow.gbr.ul_gbr   = ul_rate;
    fiveFlow.mbr.dl_mbr   = dl_ceil;
    fiveFlow.mbr.ul_mbr   = ul_ceil;

    fiveFlow.qfi = qfi;
    getQoSFlowMap()->update(qer_id, fiveFlow, BPF_ANY);

    uint16_t minor = (ntohs(seid) * 256) + (qfi * 251 % 256);
    cmd            = fmt::format(
        "tc class add dev {} parent 1:{} classid {}:{} htb rate {}kbit ceil "
        "{}kbit",
        GTP_INTERFACE, seid, seid, minor, dl_rate, dl_ceil);
    rc = system((const char*) cmd.c_str());

    Logger::upf_app().debug("    HTB Class ID (QER) ........... %d", qer_id);
    Logger::upf_app().debug("         Class QFI:      %d", qfi);
    Logger::upf_app().debug("         Class DL Rate:     %dkbps", dl_rate);
    Logger::upf_app().debug("         Class DL Ceil:     %dkbps", dl_ceil);
  }

  Logger::upf_app().info("Attach Section tc_filter_traffic to gtp interface");
  mpLifeCycle->tcAttachEgress("tc_filter_traffic", GTP_INTERFACE.c_str());

  Logger::upf_app().info("Attach Sesction tc_redirect to udp interface");
  mpLifeCycle->tcAttachIngress("tc_redirect_traffic", UDP_INTERFACE.c_str());
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
