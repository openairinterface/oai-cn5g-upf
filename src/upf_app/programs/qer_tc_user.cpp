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
#include "filter_key.h"

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

/***** Adapted from commit: 24f4c7b80e783cd16ef4c4762283dff797450f79 *****/
/*---------------------------------------------------------------------------------------------------------------*/
void QERProgram::build_pdr_map(
  const std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs) {
pdr_map.clear();
for (const auto& pdr : pdrs) {
  if (pdr && pdr->qer_id.first) {
    // Log the id for the PDR and the QER
    Logger::upf_app().debug(
        "PDR ID: %d, QER ID: %d", pdr->pdr_id.rule_id,
        pdr->qer_id.second.qer_id);
    pdr_map[pdr->qer_id.second.qer_id] = pdr;
  }
}
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<pfcp::pfcp_pdr> QERProgram::get_pdr_by_qer_id(
  uint32_t qer_id) const {
  // Print size of pdr_map
  Logger::upf_app().debug("PDR Map size: %d", pdr_map.size());
  // Find the PDR by QER ID
  Logger::upf_app().debug("Finding PDR by QER ID: %d", qer_id);
  auto it = pdr_map.find(qer_id);
  // Return the PDR if found, otherwise return nullptr
  if (it != pdr_map.end()) {
    Logger::upf_app().debug("PDR found for QER ID: %d", qer_id);
    return it->second;
  }
  Logger::upf_app().debug("PDR not found for QER ID: %d", qer_id);
  return nullptr;
}
/***** End of adaptation *****/

/*---------------------------------------------------------------------------------------------------------------*/
void QERProgram::setup(
    uint64_t seid, std::vector<std::shared_ptr<pfcp::pfcp_qer>> pQer,
    std::vector<std::shared_ptr<pfcp::pfcp_pdr>> pdrs) {
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
    Logger::upf_app().debug("Running command: %s", cmd.c_str());
    if (system(cmd.c_str()) != 0) {
      Logger::upf_app().error("Failed command: %s", cmd.c_str());
    }
  }

  Logger::upf_app().info("Create PDU Session Class 1:%d", seid);
  cmd = fmt::format(
      "tc class add dev {} parent 1:0 classid 1:1 htb rate {}kbit",
      GTP_INTERFACE, MAX_RATE);
  Logger::upf_app().debug("Running command: %s", cmd.c_str());
  if (system(cmd.c_str()) != 0) {
    Logger::upf_app().error("Failed command: %s", cmd.c_str());
  }

  Logger::upf_app().debug("QDISC Root DL Rate (GBR) : %dkbps", MAX_RATE);
  Logger::upf_app().debug("QDISC Root DL Ceil (MBR) : %dkbps", MAX_CEIL);

  build_pdr_map(pdrs);

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
      Logger::upf_app().debug("QFI not equal to default QFI: %d", qfi);
      Logger::upf_app().debug("dl_gbr: %d", qer->gbr.second.dl_gbr);
      if (qer->gbr.second.dl_gbr != 0) dl_rate = qer->gbr.second.dl_gbr;

      Logger::upf_app().debug("ul_gbr: %d", qer->gbr.second.ul_gbr);
      if (qer->gbr.second.ul_gbr != 0) ul_rate = qer->gbr.second.ul_gbr;

      Logger::upf_app().debug("dl_mbr: %d", qer->mbr.second.dl_mbr);
      if (qer->mbr.second.dl_mbr != 0) dl_ceil = qer->mbr.second.dl_mbr;

      Logger::upf_app().debug("ul_mbr: %d", qer->mbr.second.ul_mbr);
      if (qer->mbr.second.ul_mbr != 0) ul_ceil = qer->mbr.second.ul_mbr;

      Logger::upf_app().debug("dl_gate: %d", qer->gate_status.second.dl_gate);
      dl_gate = qer->gate_status.second.dl_gate;
      Logger::upf_app().debug("ul_gate: %d", qer->gate_status.second.ul_gate);
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

    Logger::upf_app().debug("Create minor from QFI %d and SEID %d", qfi, seid);

    uint32_t minor = GET_TC_CLASSID(seid, qfi); //  (ntohs(seid) * 256) + (qfi * 251 % 256);

    // Convert the minor to hex string
    std::string minor_hex = fmt::format("{:x}", minor);
    // TODO [QOS]: Remove the class when the QER is removed or UE is detached
    Logger::upf_app().debug("Create QER Class 1:%d", minor);
    cmd            = fmt::format(
        "tc class add dev {} parent 1:1 classid 1:{} htb rate {}kbit ceil "
        "{}kbit",
        GTP_INTERFACE, minor_hex, dl_rate, dl_ceil);
    
    Logger::upf_app().debug("Running command: %s", cmd.c_str());

    if (system(cmd.c_str()) != 0) {
      Logger::upf_app().error("Failed command: %s", cmd.c_str());
    }
    

    Logger::upf_app().debug("    HTB Class ID (QER) ........... %d", qer_id);
    Logger::upf_app().debug("         Class QFI:      %d", qfi);
    Logger::upf_app().debug("         Class DL Rate:     %dkbps", dl_rate);
    Logger::upf_app().debug("         Class DL Ceil:     %dkbps", dl_ceil);

    // Create the default class
    Logger::upf_app().info("Create Default Class 1:%d", DEFAULT_QFI);
    cmd = fmt::format(
        "tc class add dev {} parent 1:0 classid 1:{} htb rate {}kbit ceil "
        "{}kbit",
        GTP_INTERFACE, DEFAULT_QFI, MAX_RATE, MAX_CEIL);
    Logger::upf_app().debug("Running command: %s", cmd.c_str());
    if (system(cmd.c_str()) != 0) {
      Logger::upf_app().error("Failed command: %s", cmd.c_str());
    }


    /***** Adapted from commit: 24f4c7b80e783cd16ef4c4762283dff797450f79 *****/
    // Parse the SDF Flow Description
    std::shared_ptr<pfcp::pfcp_pdr> pdr = get_pdr_by_qer_id(qer_id);
    if (pdr == nullptr) {
      Logger::upf_app().error("PDR not found for QER %d", qer_id);
      continue;
    }
    pfcp::pdi pdi;
    pfcp::sdf_filter_t sdf;
    // std::string flowDescription = nullptr;
    pdr->get(pdi);
    pdi.get(sdf);

    // if (sdf.fd && sdf.length_of_flow_description > 0)
    //   flowDescription = std::string(sdf.flow_label);

    // Logger::upf_app().debug("         Flow Description: %s", flowDescription.c_str());

    struct filter_key sdf_filter_key = {};
    sdf_filter_key.src_ip            = 0;
    // TODO [QOS]: Support dynamic setting of dst_ip, for now set it to UE IP since it's only for downlink
    sdf_filter_key.dst_ip            = pdi.ue_ip_address.second.ipv4_address.s_addr;
    // TODO [QOS]: Support for protocol
    sdf_filter_key.protocol          = 0;
    // TODO [QOS]: Support for dst_port
    sdf_filter_key.dst_port          = 0;
    // TODO [QOS] Support for src_port
    // sdf_filter_key.src_port          = 0;
    // TODO [QOS] Support for TOS
    sdf_filter_key.tos              = 0; 

    
    struct session_qfi sdf_filter_value = {};
    sdf_filter_value.qfi = qfi;
    sdf_filter_value.seid = seid;

    getSdfFilterMap()->update(sdf_filter_key, sdf_filter_value, BPF_ANY);
     
    /***** End of adaptation *****/

  }

  Logger::upf_app().info("Attach Section tc_filter_traffic to gtp interface");
  // mpLifeCycle->tcAttachEgress("tc_filter_traffic", GTP_INTERFACE.c_str());

  if(no_tc_filter_bpf(GTP_INTERFACE)) {
    Logger::upf_app().info("Attach Section tc_filter_traffic to gtp interface");
    // Create tc filter for the GTP interface
    cmd = fmt::format(
        "tc filter add dev {} parent 1:0 protocol ip bpf obj /openair-upf/bin/qer_tc_kernel.c.o classid 1: direct-action",
        GTP_INTERFACE.c_str());
    Logger::upf_app().debug("Running command: %s", cmd.c_str());
    if (system(cmd.c_str()) != 0) {
      Logger::upf_app().error("Failed command: %s", cmd.c_str());
    }
  }
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
