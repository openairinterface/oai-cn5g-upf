#include "pfcp_session_lookup_ebpf_xdp_prgrm_user.h"
#include <SessionManager.h>
#include <bpf/bpf.h>     // bpf calls
#include <bpf/libbpf.h>  // bpf wrappers
#include <iostream>      // cout
#include <stdexcept>     // exception
#include <wrappers/BPFMap.hpp>
#include <wrappers/BPFMaps.h>
#include "interfaces.h"
#include "logger.hpp"

// Define constants for the parameters
// #define TYPE_DELAY_CRITICAL_GBR "Delay Critical GBR"
// #define TYPE_GBR "GBR"
// #define TYPE_NON_GBR "Non-GBR"

// #define QOS_3 3
// #define QOS_10 10
// #define QOS_30 30
// #define QOS_100 100
// #define QOS_300 300
// #define QOS_1000 1000
// #define QOS_5000 5000
// //#define QOS_10000 10000
// #define QOS_DEFAULT 10000

// #define QFI_1 1
// #define QFI_2 2
// #define QFI_3 3
// #define QFI_4 4
// #define QFI_5 5
// #define QFI_6 6
// #define QFI_7 7
// //#define QFI_8 8
// #define QFI_DEFALUT 8

// #define DSCP_39 39  // 100111
// #define DSCP_38 38  // 100110
// #define DSCP_21 21  // 010101
// #define DSCP_20 20  // 010100
// #define DSCP_19 19  // 010011
// #define DSCP_10 10  // 001010
// #define DSCP_9 9    // 001001
// //#define DSCP_8 8        // 001000
// #define DSCP_DEFAULT 0  // 000000

/*****************************************************************************************************************/

int is_little_endian2() {
  u32 value = 1;
  u8* byte  = (u8*) &value;
  return (*byte == 1);
}

/*****************************************************************************************************************/
PFCP_Session_LookupProgram::PFCP_Session_LookupProgram(
    const std::string& gtpInterface, const std::string& udpInterface)
    : mGTPInterface(gtpInterface), mUDPInterface(udpInterface) {
  mpLifeCycle = std::make_shared<PFCP_Session_LookupProgramLifeCycle>(
      pfcp_session_lookup_ebpf_xdp_prgrm_kernel_c__open,
      pfcp_session_lookup_ebpf_xdp_prgrm_kernel_c__load,
      pfcp_session_lookup_ebpf_xdp_prgrm_kernel_c__attach,
      pfcp_session_lookup_ebpf_xdp_prgrm_kernel_c__destroy);
}

/*****************************************************************************************************************/
PFCP_Session_LookupProgram::~PFCP_Session_LookupProgram() {}

/*****************************************************************************************************************/
void PFCP_Session_LookupProgram::setup() {
  spSkeleton = mpLifeCycle->open();
  initializeMaps();
  mpLifeCycle->load();
  mpLifeCycle->attach();

  // Entry point interface
  if (mUDPInterface.empty() || mGTPInterface.empty()) {
    Logger::upf_app().error("GTP or UDP interface not defined!");
    throw std::runtime_error("GTP or UDP interface not defined!");
  }

  Logger::upf_app().debug(
      "Link UDP interface to interface %s", mUDPInterface.c_str());
  mpLifeCycle->link("xdp_entry_point", mUDPInterface.c_str());

  Logger::upf_app().debug(
      "Link GTP interface to interface %s", mGTPInterface.c_str());
  mpLifeCycle->link("xdp_entry_point", mGTPInterface.c_str());

  // Use the defined constants in the function calls
  // instrementQfiFlowMappingTable(DELAY_CRITICAL_GBR, QOS_3, QFI_1, DSCP_39);
  // instrementQfiFlowMappingTable(DELAY_CRITICAL_GBR, QOS_10, QFI_2, DSCP_38);
  // instrementQfiFlowMappingTable(GBR, QOS_30, QFI_3, DSCP_21);
  // instrementQfiFlowMappingTable(GBR, QOS_100, QFI_4, DSCP_20);
  // instrementQfiFlowMappingTable(GBR, QOS_300, QFI_5, DSCP_19);
  // instrementQfiFlowMappingTable(NON_GBR, QOS_1000, QFI_6, DSCP_10);
  // instrementQfiFlowMappingTable(NON_GBR, QOS_5000, QFI_7, DSCP_9);
  // // instrementQfiFlowMappingTable(NON_GBR, QOS_10000, QFI_8, DSCP_8);
  // instrementQfiFlowMappingTable(
  //     NON_GBR, QOS_DEFAULT, QFI_DEFALUT, DSCP_DEFAULT);
}

/*****************************************************************************************************************/
std::shared_ptr<BPFMaps> PFCP_Session_LookupProgram::getMaps() {
  return mpMaps;
}

/*****************************************************************************************************************/
// TODO: Check when kill when running.
// It was noted the infinity loop.
void PFCP_Session_LookupProgram::tearDown() {
  mpLifeCycle->tearDown();
}

/*****************************************************************************************************************/
void PFCP_Session_LookupProgram::updateProgramMap(uint32_t key, uint32_t fd) {
  mpTeidSessionMap->update(key, fd, BPF_ANY);
}

/*****************************************************************************************************************/
void PFCP_Session_LookupProgram::removeProgramMap(uint32_t key) {
  s32 fd;
  // Remove only if exists.
  if (mpTeidSessionMap->lookup(key, &fd) == 0) {
    mpTeidSessionMap->remove(key);
  }
}

/*****************************************************************************************************************/
std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getTeidSessionMap() const {
  return mpTeidSessionMap;
}

/*****************************************************************************************************************/
std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getUeIpSessionMap() const {
  return mpUeIpSessionMap;
}

/*****************************************************************************************************************/
std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getNextProgRuleMap() const {
  return mpNextProgRuleMap;
}

/*****************************************************************************************************************/
std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getNextProgRuleIndexMap()
    const {
  return mpNextProgRuleIndexMap;
}

/*****************************************************************************************************************/

std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getSessionMappingMap()
    const {
  return mpSessionMappingMap;
}

// /*****************************************************************************************************************/
// std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getTrafficMap() const {
//   return mpTrafficMap;
// }

// /*****************************************************************************************************************/

// std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getUeQfiTeidMap() const {
//   return mpUeQfiTeidMap;
// }

// /*****************************************************************************************************************/

// std::shared_ptr<BPFMap> PFCP_Session_LookupProgram::getQosFlowMap() const {
//   return mpQosFlowMap;
// }

/*****************************************************************************************************************/

void PFCP_Session_LookupProgram::initializeMaps() {
  // Store all maps available in the program.
  mpMaps = std::make_shared<BPFMaps>(mpLifeCycle->getBPFSkeleton()->skeleton);

  // Warning - The name of the map must be the same of the BPF program.
  mpTeidSessionMap = std::make_shared<BPFMap>(mpMaps->getMap("m_teid_session"));
  mpUeIpSessionMap = std::make_shared<BPFMap>(mpMaps->getMap("m_ueip_session"));
  mpNextProgRuleMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_next_rule_prog"));
  mpNextProgRuleIndexMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_next_rule_prog_index"));
  mpSessionMappingMap =
      std::make_shared<BPFMap>(mpMaps->getMap("m_session_mapping"));
  // mpTrafficMap =
  //     std::make_shared<BPFMap>(mpMaps->getMap("m_traffic_classification"));
  // mpUeQfiTeidMap = std::make_shared<BPFMap>(mpMaps->getMap("m_ue_qfi_teid"));
  // mpQosFlowMap   =
  // std::make_shared<BPFMap>(mpMaps->getMap("m_qos_flow_map"));
}

/*****************************************************************************************************************/

// void PFCP_Session_LookupProgram::instrementQfiFlowMappingTable(
//     e_resource_type type, uint32_t qos, uint8_t qfi, uint8_t dscp) {
//   struct s_qfi_parameters value;
//   __builtin_memset(&value, 0, sizeof(struct s_qfi_parameters));

//   if (is_little_endian2()) {
//     value.qos = htole32(qos);
//   } else {
//     value.qos = qos;
//   }

//   value.resource_type = type;
//   value.qfi           = qfi;

//   getQosFlowMap()->update(dscp, value, BPF_ANY);
// }