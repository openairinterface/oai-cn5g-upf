#include "qer_tc_user.h"
#include <SessionManager.h>
#include <bpf/bpf.h>     // bpf calls
#include <bpf/libbpf.h>  // bpf wrappers
#include <iostream>      // cout
#include <stdexcept>     // exception
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "interfaces.h"
#include "logger.hpp"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netlink/route/link.h>
#include <netlink/route/qdisc/htb.h>
#include <NetlinkManager.h>
#include "standardized_5qi.h"
#include "helpers/GetNicInformation.hpp"
#include "helpers/CmdRunner.hpp"
//#include "standardized_5qi_qos_mapping.h"
//#include "qer_maps.h"

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
// // Method definition to initialize class_params
// void QERProgram::setPduSessionClassAttributes(
//     const char* qdiscScheduler, std::string interface) {
//   NicInformationGetter nicConfiguration;
//   // Initialize classAtt members
//   pduSessionClassAtt            = new classParams();
//   pduSessionClassAtt->scheduler = qdiscScheduler;
//   pduSessionClassAtt->rate      =
//   NicInformationGetter::retrieveRate(interface); pduSessionClassAtt->ceil =
//   NicInformationGetter::retrieveCeil(interface); pduSessionClassAtt->burst =
//   NicInformationGetter::retrieveBurst(interface); pduSessionClassAtt->cburst
//   = NicInformationGetter::retrieveCBurst(interface);
//   pduSessionClassAtt->priority  = -1;

//   Logger::upf_app().debug(
//       "QDISC Root Rate (GBR) : %d", pduSessionClassAtt->rate);
//   Logger::upf_app().debug(
//       "QDISC Root Ceil (MBR) : %d", pduSessionClassAtt->ceil);
//   Logger::upf_app().debug(
//       "QDISC Root Burst      : %d", pduSessionClassAtt->burst);
//   Logger::upf_app().debug(
//       "QDISC Root CBurst     : %d", pduSessionClassAtt->cburst);
//   Logger::upf_app().debug(
//       "QDISC Root Priority   : %d", pduSessionClassAtt->priority);
// }

/*---------------------------------------------------------------------------------------------------------------*/
// Method definition to initialize class_params
// void QERProgram::setQosFlowsClassesAttributes() {
//   for (int i = 0; i < savedQers.size() && i < qosFlowsQfis.size(); ++i) {
//     const auto& qer              = savedQers[i];
//     struct classParams* classAtt = new classParams();

//     classAtt->scheduler = pduSessionClassAtt->scheduler;
//     if (qosFlowsQfis[i].qfi != DEFAULT_QFI) {
//       classAtt->rate     = qosFlowsQfis[i].gbr.dl_gbr;
//       classAtt->ceil     = qosFlowsQfis[i].mbr.dl_mbr;
//       classAtt->burst    = 0;
//       classAtt->cburst   = 0;
//       classAtt->priority = -1;
//     } else {
//       classAtt->rate     = 100;
//       classAtt->ceil     = 200;
//       classAtt->burst    = 0;
//       classAtt->cburst   = 0;
//       classAtt->priority = -1;
//     }

//     qosFlowsClassesAtt.push_back(classAtt);

//     Logger::upf_app().debug(
//         "    HTB Class ID (QER) ........... %d",
//         savedQers[i]->qer_id.second.qer_id);
//     Logger::upf_app().debug("         Class QFI:      %d",
//     qosFlowsQfis[i].qfi); Logger::upf_app().debug("         Class Rate:
//     %dkbps", classAtt->rate); Logger::upf_app().debug("         Class Ceil:
//     %dkbps", classAtt->ceil); Logger::upf_app().debug("         Class Burst:
//     %d", classAtt->burst); Logger::upf_app().debug("         Class CBurst:
//     %d", classAtt->cburst); Logger::upf_app().debug("         Class Priority:
//     %d", classAtt->priority);
//   }
// }

// /*---------------------------------------------------------------------------------------------------------------*/
// // Method definition to set pduSession class position
// void QERProgram::setPduSessionClassPosition(uint64_t seid) {
//   pduSessionClassPos            = new classPosition();
//   pduSessionClassPos->parentMaj = 1;
//   pduSessionClassPos->parentMin = 0;
//   pduSessionClassPos->childMaj  = 1;
//   pduSessionClassPos->childMin  = seid;
// }

// /*---------------------------------------------------------------------------------------------------------------*/
// // Method definition to set pduSession class position
// void QERProgram::setQosFlowsClassesPositions() {
//   for (int i = 0; i < qosFlowsQfis.size(); i++) {
//     struct classPosition* classPos = new classPosition();

//     classPos->parentMaj = pduSessionClassPos->parentMaj;
//     classPos->parentMin = pduSessionClassPos->parentMin;
//     classPos->childMaj  = pduSessionClassPos->childMin;
//     classPos->childMin  = qosFlowsQfis[i].qfi;

//     qosFlowsClassesPos.push_back(classPos);

//     Logger::upf_app().debug(
//         "QDISC Root Position: %d:%d", classPos->parentMaj,
//         classPos->parentMin);
//     Logger::upf_app().debug(
//         "QDISC Root-Child Position: %d:%d", classPos->childMaj,
//         classPos->childMin);
//     Logger::upf_app().debug(
//         "HTB Class Position  %d:%d", classPos->childMaj, classPos->childMin);
//   }
// }
/*---------------------------------------------------------------------------------------------------------------*/

bool no_htb_root_qdisc(std::string interface) {
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
  QdiscHelper qdiscHelper;
  spSkeleton = mpLifeCycle->open();
  initializeMaps();
  mpLifeCycle->load();
  mpLifeCycle->attach();

  // savedQers = pQer;

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
      "tc class add dev {} parent 1:0 classid 1:{} htb rate {}", GTP_INTERFACE,
      seid, MAX_RATE);
  rc = system((const char*) cmd.c_str());

  Logger::upf_app().debug("QDISC Root Rate (GBR) : %dMbps", MAX_RATE);
  Logger::upf_app().debug("QDISC Root Ceil (MBR) : %dMbps", MAX_CEIL);

  for (const auto& qer : pQer) {
    Logger::upf_app().error("======================================0");
    if (qer == nullptr) {
      Logger::upf_app().error(
          "======================================1111111111111111111111");
      continue;
    }
    uint8_t qfi = qer->qfi.second.qfi;
    Logger::upf_app().error("======================================1");
    uint64_t dl_rate = DEFAULT_RATE;
    uint64_t dl_ceil = DEFAULT_CEIL;
    uint64_t ul_rate = DEFAULT_RATE;
    uint64_t ul_ceil = DEFAULT_CEIL;
    Logger::upf_app().error("======================================2");
    uint32_t qer_id = qer->qer_id.second.qer_id;
    Logger::upf_app().error("======================================3");
    uint8_t dl_gate = 0;
    uint8_t ul_gate = 0;

    if (qfi != DEFAULT_QFI) {
      Logger::upf_app().error("======================================4");
      dl_rate = qer->gbr.second.dl_gbr;
      ul_rate = qer->gbr.second.ul_gbr;

      dl_ceil = qer->mbr.second.dl_mbr;
      ul_ceil = qer->mbr.second.ul_mbr;

      dl_gate = qer->gate_status.second.dl_gate;
      ul_gate = qer->gate_status.second.ul_gate;
    }
    Logger::upf_app().error("======================================5");
    struct s_fiveQosFlow fiveFlow;
    memset(&fiveFlow, 0, sizeof(struct s_fiveQosFlow));

    fiveFlow.gate.dl_gate = dl_gate;
    fiveFlow.gate.ul_gate = ul_gate;
    fiveFlow.gbr.dl_gbr   = dl_rate;
    fiveFlow.gbr.ul_gbr   = ul_rate;
    fiveFlow.mbr.dl_mbr   = dl_ceil;
    fiveFlow.mbr.ul_mbr   = ul_ceil;

    fiveFlow.qfi = qfi;
    Logger::upf_app().error("======================================6");
    getQoSFlowMap()->update(qer_id, fiveFlow, BPF_ANY);

    cmd = fmt::format(
        "tc class add dev {} parent 1:{} classid {}:{} htb rate {} ceil {}",
        GTP_INTERFACE, seid, seid, qfi, dl_rate, dl_ceil);
    rc = system((const char*) cmd.c_str());

    Logger::upf_app().debug("    HTB Class ID (QER) ........... %d", qer_id);
    Logger::upf_app().debug("         Class QFI:      %d", qfi);
    Logger::upf_app().debug("         Class Rate:     %dkbps", dl_rate);
    Logger::upf_app().debug("         Class Ceil:     %dkbps", dl_ceil);
  }

  cmd = fmt::format("tc qdisc add dev {} clsact", GTP_INTERFACE);
  rc  = system((const char*) cmd.c_str());

  cmd = fmt::format(
      "tc filter add dev {} ingress parent 1:0 bpf obj "
      "/sys/fs/bpf/qer_tc_kernel sec classifier/cls_filter",
      GTP_INTERFACE);
  rc = system((const char*) cmd.c_str());

  cmd = fmt::format("tc qdisc add dev {} clsact", UDP_INTERFACE);
  rc  = system((const char*) cmd.c_str());

  cmd = fmt::format(
      "tc filter add dev {} egress bpf obj /sys/fs/bpf/qer_udp_tc_kernel sec "
      "classifier/tc_redirect",
      UDP_INTERFACE);
  rc = system((const char*) cmd.c_str());

  // for (int i = 0; i < qosFlowsClassesAtt.size(); i++) {
  //   cmd = fmt::format(
  //       "tc class add dev {} parent 1:{} classid {}:{} htb rate {} ceil {}",
  //       gtpInterface, seid, seid, qosFlowsClassesPos[i]->childMin,
  //       qosFlowsClassesAtt[i]->rate, qosFlowsClassesAtt[i]->ceil);
  //   rc = system((const char*) cmd.c_str());
  // }
  // cmd = fmt::format("tc qdisc add dev {} clsact", gtpInterface);
  // rc  = system((const char*) cmd.c_str());

  // cmd = fmt::format(
  //     "tc filter add dev {} ingress parent 1:0 bpf obj "
  //     "/sys/fs/bpf/qer_tc_kernel sec classifier/cls_filter",
  //     gtpInterface);
  // rc = system((const char*) cmd.c_str());

  // cmd = fmt::format("tc qdisc add dev {} clsact", udpInterface);
  // rc  = system((const char*) cmd.c_str());

  // cmd = fmt::format(
  //     "tc filter add dev {} egress bpf obj /sys/fs/bpf/qer_udp_tc_kernel sec
  //     " "classifier/tc_redirect", udpInterface);
  // rc = system((const char*) cmd.c_str());
}

/*---------------------------------------------------------------------------------------------------------------*/
void QERProgram::setup() {
  spSkeleton = mpLifeCycle->open();
  initializeMaps();
  mpLifeCycle->load();
  mpLifeCycle->attach();
  // insertValuesIntoMaps();
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
std::shared_ptr<BPFMap> QERProgram::geGtpUTunnelMap() const {
  return mpGtpUTunnelMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
// std::shared_ptr<BPFMap> QERProgram::getFilterMap() const {
//   return mpFilterMap;
// }

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
  mpGtpUTunnelMap = std::make_shared<BPFMap>(mpMaps->getMap("m_gtp_u_tunnel"));
  // mpFilterMap     = std::make_shared<BPFMap>(mpMaps->getMap("m_filter"));
  mp5GQoSFlowParamsMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_5g_qos_flow_parameters"));
  mpQoSFlowMap   = std::make_shared<BPFMap>(mpMaps->getMap("m_qos_flow"));
  mpSdfFilterMap = std::make_shared<BPFMap>(mpMaps->getMap("m_sdf_filter"));
  mpEgressIfindexMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_egress_ifindex"));
}
