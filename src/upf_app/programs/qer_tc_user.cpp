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

// #define EGRESS_HANDLE 0x1
// #define EGRESS_PRIORITY 0xC02F

// #define INGRESS_HANDLE 0x1
// #define INGRESS_PRIORITY 0xC02F
#define DEFAULT_CLASS_HANDLE 65535
#define DEFAULT_CLASS_RATE 1024 /*kbit*/
#define DEFAULT_CLASS_CEIL 2048 /*kbit*/
#define R2Q_ROOT 5
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

/*---------------------------------------------------------------------------------------------------------------*/
static inline uint16_t generate_minor_id(uint64_t seid, uint8_t qfi) {
  uint16_t hash = (seid ^ (seid >> 16) ^ (seid >> 32) ^ (seid >> 48));
  uint16_t minor_id =
      (hash + (qfi * 37)) & 0xFFFF;  // Avoid modulo, use bitmask

  // Limit minor_id to a max of 9999
  minor_id = (minor_id > 9999) ? 9999 : minor_id;

  return minor_id ? minor_id : 1;  // Ensure nonzero
}
/*---------------------------------------------------------------------------------------------------------------*/
void QERProgram::setup(
    uint64_t seid, std::vector<std::shared_ptr<pfcp::pfcp_qer>> pQer,
    std::vector<std::shared_ptr<pfcp::pfcp_pdr>> pdrs) {
  spSkeleton = mpLifeCycle->open();

  initializeMaps();
  mpLifeCycle->load();
  mpLifeCycle->attach();

  std::shared_ptr<pfcp::pfcp_qer> default_qer =
      retrive_default_qer_with_default_qfi(pQer);

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
    // Configure Root Qdisc if not already present
    if (no_htb_root_qdisc(GTP_INTERFACE)) {
      Logger::upf_app().info(
          "Create Root qdisc on interface %s with Default Class: %d, and r2q: "
          "%d",
          GTP_INTERFACE.c_str(), DEFAULT_CLASS_HANDLE, R2Q_ROOT);

      // default_qer = retrive_default_qer_with_default_qfi(pQer);

      // if (default_qer) {
      //   int key             = 0;
      //   uint8_t default_qfi = default_qer->qfi.second.qfi;
      //   getDefaultQfiMap()->update(key, default_qfi, BPF_ANY);
      //   cmd = fmt::format(
      //       "tc qdisc add dev {} root handle 1:0 htb default {}",
      //       GTP_INTERFACE,
      //       static_cast<uint8_t>(default_qer->qfi.second.qfi));
      //   // rc = system((const char*) cmd.c_str());
      // } else {
      //   Logger::upf_app().info(
      //       "QER with default QFI not found, creating HTB root Qdisc without
      //       " "default class");
      //   cmd = fmt::format(
      //       "tc qdisc add dev {} root handle 1:0 htb", GTP_INTERFACE);
      // }

      cmd = fmt::format(
          "tc qdisc add dev {} root handle 1:0 htb default {} r2q {}",
          GTP_INTERFACE, DEFAULT_CLASS_HANDLE, R2Q_ROOT);

      if (system(cmd.c_str()) != 0) {
        Logger::upf_app().error("Failed command: %s", cmd);
        return;
      }

      Logger::upf_app().debug("QDISC Root DL Rate (GBR) : %dkbps", MAX_RATE);
      Logger::upf_app().debug("QDISC Root DL Ceil (MBR) : %dkbps", MAX_CEIL);
    } else {
      // if (no_htb_default_class(GTP_INTERFACE) && default_qer) {
      //   cmd = fmt::format(
      //       "tc qdisc change dev {} root handle 1:0 htb default {}",
      //       GTP_INTERFACE,
      //       static_cast<uint8_t>(default_qer->qfi.second.qfi));

      //   if (system(cmd.c_str()) != 0) {
      //     Logger::upf_app().error("Failed command: %s", cmd);
      //   }
      // }
      Logger::upf_app().debug(
          "HTB Root qdisc on interface %s already created",
          GTP_INTERFACE.c_str());
    }

    // Create PDU Session Class
    Logger::upf_app().info(
        "Create PDU Session Class 1:%d with rate: %d", seid, MAX_RATE);
    cmd = fmt::format(
        "tc class add dev {} parent 1: classid 1:{} htb rate {}kbit",
        GTP_INTERFACE, seid, MAX_RATE);

    if (system(cmd.c_str()) != 0) {
      Logger::upf_app().error("Failed command: %s", cmd);
    }

    // Process each QER
    // struct sdf_filtr sdfFilter;
    // std::string flowDescription;
    // uint32_t key = 0;
    build_pdr_map(pdrs);

    for (const auto& qer : pQer) {
      uint8_t qfi    = qer->qfi.second.qfi;
      uint16_t minor = generate_minor_id(seid, qfi);
      //(ntohs(seid) * 256) + ((qfi * 251) % 256);

      if (qer == default_qer) {
        uint16_t default_minor = (DEFAULT_CLASS_HANDLE - minor) % 10000;
        //(ntohs(seid) * 256) + (DEFAULT_CLASS_HANDLE * 251 % 256);

        Logger::upf_app().info(
            "Create Default Class 1:%d Child of Parent 1:%d", default_minor,
            seid);
        Logger::upf_app().info(
            "The Default Class 1:%d is of Rate: %d kbit and Ceil: %d kbit",
            default_minor, DEFAULT_CLASS_RATE, DEFAULT_CLASS_CEIL);

        cmd = fmt::format(
            "tc class add dev {} parent 1:{} classid 1:{} htb rate {}kbit "
            "ceil "
            "{}kbit",
            GTP_INTERFACE, seid, default_minor, DEFAULT_CLASS_RATE,
            DEFAULT_CLASS_CEIL);

        if (system(cmd.c_str()) != 0) {
          Logger::upf_app().error("Failed command: %s", cmd);
        } else {
          Logger::upf_app().info(
              "Create PFIFO default class %d: Child of Parent 1:%d", minor,
              default_minor, seid);
          cmd = fmt::format(
              "tc class add dev {} parent 1:{} classid 1:{} htb rate {}kbit "
              "ceil {}kbit",
              GTP_INTERFACE, default_minor, minor, DEFAULT_CLASS_RATE,
              DEFAULT_CLASS_CEIL);

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

        // Update QoS flow map
        struct s_fiveQosFlow fiveFlow = {};
        fiveFlow.gate                 = dl_gate;
        fiveFlow.gbr                  = dl_rate;
        fiveFlow.mbr                  = dl_ceil;

        getQoSFlowMap()->update(qer_id, fiveFlow, BPF_ANY);

        // Add tc class for QER
        // Create QoS Flow Class for Session
        Logger::upf_app().info(
            "Create QoS Flow Class 1:%d for PDU Session Parent 1:%d", minor,
            seid);

        cmd = fmt::format(
            "tc class add dev {} parent 1:{} classid 1:{} htb rate {}kbit "
            "ceil "
            "{}kbit",
            GTP_INTERFACE, seid, minor, dl_rate, dl_ceil);

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

    Logger::upf_app().info("Attach Section tc_filter_traffic to gtp interface");
    mpLifeCycle->tcAttachEgress("tc_filter_traffic", GTP_INTERFACE.c_str());

    Logger::upf_app().info("Attach Section tc_redirect to udp interface");
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
std::shared_ptr<BPFMap> QERProgram::getDefaultQfiMap() const {
  return mpDefaultQfiMap;
}
/*---------------------------------------------------------------------------------------------------------------*/
void QERProgram::initializeMaps() {
  // Store all maps available in the program.
  mpMaps = std::make_shared<BPFMaps>(mpLifeCycle->getBPFSkeleton()->skeleton);

  // Warning - The name of the map must be the same of the BPF program.
  mpQoSFlowMap = std::make_shared<BPFMap>(mpMaps->getMap("m_qos_flow"));

  mpEgressIfindexMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_egress_ifindex"));
  mpDefaultQfiMap = std::make_shared<BPFMap>(mpMaps->getMap("m_default_qfi"));
}
