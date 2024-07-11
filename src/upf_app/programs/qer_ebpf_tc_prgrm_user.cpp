#include "qer_ebpf_tc_prgrm_user.h"
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
//#include "standardized_5qi_qos_mapping.h"
//#include "qer_maps.h"

const u32 QI_1 = 1;
const u32 QI_2 = 2;
const u32 QI_3 = 3;
const u32 QI_4 = 4;
const u32 QI_5 = 5;
const u32 QI_6 = 6;
const u32 QI_7 = 7;
const u32 QI_8 = 8;
const u32 QI_9 = 9;
const u32 QI_65 = 65;
const u32 QI_66 = 66;
const u32 QI_67 = 67;
const u32 QI_69 = 69;
const u32 QI_70 = 70;
const u32 QI_71 = 71;
const u32 QI_72 = 72;
const u32 QI_73 = 73;
const u32 QI_74 = 74;
const u32 QI_75 = 75;
const u32 QI_76 = 76;
const u32 QI_79 = 79;
const u32 QI_80 = 80;
const u32 QI_82 = 82;
const u32 QI_83 = 83;
const u32 QI_84 = 84;
const u32 QI_85 = 85;
const u32 QI_86 = 86;
// Define the global QosFlowParams instances
/*
* GBR
*/
const QosFlowParams FIVE_QI_1 =  {GBR, 20, 100, 1e-2, 0, 2000};
const QosFlowParams FIVE_QI_2 =  {GBR, 40, 150, 1e-3, 0, 2000};
const QosFlowParams FIVE_QI_3 =  {GBR, 30, 50,  1e-3, 0, 2000};
const QosFlowParams FIVE_QI_4 =  {GBR, 50, 300, 1e-6, 0, 2000};
const QosFlowParams FIVE_QI_65 = {GBR, 7,  75,  1e-2, 0, 2000};
const QosFlowParams FIVE_QI_66 = {GBR, 20, 100, 1e-2, 0, 2000};
const QosFlowParams FIVE_QI_67 = {GBR, 15, 100, 1e-3, 0, 2000};
const QosFlowParams FIVE_QI_71 = {GBR, 56, 150, 1e-6, 0, 2000};
const QosFlowParams FIVE_QI_72 = {GBR, 56, 300, 1e-4, 0, 2000};
const QosFlowParams FIVE_QI_73 = {GBR, 56, 300, 1e-8, 0, 2000};
const QosFlowParams FIVE_QI_74 = {GBR, 56, 500, 1e-8, 0, 2000};
const QosFlowParams FIVE_QI_75 = {GBR, 00, 000, 0000, 0, 0000};
const QosFlowParams FIVE_QI_76 = {GBR, 56, 500, 1e-4, 0, 2000};

/*
* Non-GBR
*/
const QosFlowParams FIVE_QI_5 =  {NON_GBR, 10, 100, 1e-6, 0, 0};
const QosFlowParams FIVE_QI_6 =  {NON_GBR, 60, 300, 1e-6, 0, 0};
const QosFlowParams FIVE_QI_7 =  {NON_GBR, 70, 100, 1e-3, 0, 0};
const QosFlowParams FIVE_QI_8 =  {NON_GBR, 80, 300, 1e-6, 0, 0};
const QosFlowParams FIVE_QI_9 =  {NON_GBR, 90, 300, 1e-6, 0, 0};
const QosFlowParams FIVE_QI_69 = {NON_GBR, 5,  60,  1e-6, 0, 0};
const QosFlowParams FIVE_QI_70 = {NON_GBR, 55, 200, 1e-6, 0, 0};
const QosFlowParams FIVE_QI_79 = {NON_GBR, 65, 50,  1e-2, 0, 0};
const QosFlowParams FIVE_QI_80 = {NON_GBR, 68, 10,  1e-6, 0, 0};

/*
* Delay Critical GBR
*/
const QosFlowParams FIVE_QI_82 = {DELAY_CRITICAL_GBR, 19, 10, 1e-4, 0, 0000};
const QosFlowParams FIVE_QI_83 = {DELAY_CRITICAL_GBR, 22, 10, 1e-4, 0, 2000};
const QosFlowParams FIVE_QI_84 = {DELAY_CRITICAL_GBR, 24, 30, 1e-5, 0, 2000};
const QosFlowParams FIVE_QI_85 = {DELAY_CRITICAL_GBR, 21, 5,  1e-5, 0, 2000};
const QosFlowParams FIVE_QI_86 = {DELAY_CRITICAL_GBR, 18, 5,  1e-4, 0, 0000};

/*---------------------------------------------------------------------------------------------------------------*/
QERProgram::QERProgram(): BPFProgram() {
  mpLifeCycle = std::make_shared<QERProgramLifeCycle>(
      qer_ebpf_tc_prgrm_kernel_c__open, qer_ebpf_tc_prgrm_kernel_c__load,
      qer_ebpf_tc_prgrm_kernel_c__attach, qer_ebpf_tc_prgrm_kernel_c__destroy);
}


/*---------------------------------------------------------------------------------------------------------------*/
QERProgram::~QERProgram() {}

/*---------------------------------------------------------------------------------------------------------------*/
void QERProgram::setup() {
  spSkeleton = mpLifeCycle->open();
  initializeMaps();
  mpLifeCycle->load();
  mpLifeCycle->attach();

  insertValuesIntoMaps();
}

/*---------------------------------------------------------------------------------------------------------------*/
/*
 *  Save the different QFI values for all QoS
 *  Flows belonging to the same PDU Session
 */
void QERProgram::setQosFlowsQfis(std::vector<struct s_fiveQosFlow*> qfis) {
  struct s_fiveQosFlow* qosFlow;
  for (int i = 0; i < sizeof(qfis); i++) {
    qosFlow->gate = qfis[i]->gate;
    
    qosFlow->mbr.dl_mbr = qfis[i]->mbr.dl_mbr;
    qosFlow->mbr.ul_mbr = qfis[i]->mbr.ul_mbr;
    
    qosFlow->gbr.dl_gbr = qfis[i]->gbr.dl_gbr;
    qosFlow->gbr.ul_gbr = qfis[i]->gbr.ul_gbr;
    
    qosFlow->qfi = qfis[i]->qfi;
    
    qosFlowsQfis.push_back(qosFlow);
  }
}

/*---------------------------------------------------------------------------------------------------------------*/
/*
 *  Save the Identifiers of the PDU Session:
 *  Seid,  teidUl,  teidDl
 */
void QERProgram::setPduSessionIds(uint64_t seid, struct gtpUTunnel* gtpTunnel) {
  pduSession->seid   = seid;
  pduSession->teidUl = gtpTunnel->teidUl;
  pduSession->teidDl = gtpTunnel->teidDl;
}

// void QERProgram::set_pduSession_ids(uint64_t seid) {
//   pduSession->seid = seid;
//   struct gtpUTunnel gtpTunnel={};

//   if ((gtpTunnel = bpf_map_lookup_elem(&m_gtpUTunnel, &seid))){
//     pduSession->teidUl = gtpTunnel->teidUl;
//     pduSession->teidDl = gtpTunnel->teidDl;
//   }

// }

/*---------------------------------------------------------------------------------------------------------------*/
// Method definition to initialize class_params
void QERProgram::setPduSessionClassAttributes(const char* qdiscScheduler) {
  // Initialize classAtt members
  pduSessionClassAtt->scheduler = qdiscScheduler;
  pduSessionClassAtt->rate      = -1;  // gbr is the correct affectation?
  pduSessionClassAtt->ceil      = -1;  // mbr is the correct affectation?
  pduSessionClassAtt->burst     = -1;
  pduSessionClassAtt->cburst    = -1;
  pduSessionClassAtt->priority  = -1;
}

/*---------------------------------------------------------------------------------------------------------------*/
// Method definition to initialize class_params
void QERProgram::setQosFlowsClassesAttributes() {
  struct classParams* classAtt;

  for (int i = 0; i < sizeof(qosFlowsQfis); i++) {
    classAtt->scheduler = pduSessionClassAtt->scheduler;
    classAtt->rate = qosFlowsQfis[i]->gbr.dl_gbr;  // check 5QI table to get this value
    classAtt->ceil = qosFlowsQfis[i]->mbr.dl_mbr;  // check 5QI to get this value
    classAtt->burst    = -1;
    classAtt->cburst   = -1;
    classAtt->priority = -1;

    qosFlowsClassesAtt.push_back(classAtt);
  }
}

/*---------------------------------------------------------------------------------------------------------------*/
// Method definition to set pduSession class position
void QERProgram::setPduSessionClassPosition() {
  pduSessionClassPos->parentMaj = 1;
  pduSessionClassPos->parentMin = 0;
  pduSessionClassPos->childMaj  = 1;
  pduSessionClassPos->childMin =
      pduSession->seid && (pduSession->teidUl && pduSession->teidDl);
}

/*---------------------------------------------------------------------------------------------------------------*/
// Method definition to set pduSession class position
void QERProgram::setQosFlowsClassesPositions() {
  struct classPosition* classPos;

  classPos->parentMaj = pduSessionClassPos->parentMaj;
  classPos->parentMin = pduSessionClassPos->parentMin;
  classPos->childMaj  = pduSessionClassPos->childMin;

  for (int i = 0; i < sizeof(qosFlowsQfis); i++) {
    classPos->childMin = qosFlowsQfis[i]->qfi;

    qosFlowsClassesPos.push_back(classPos);
  }
}

/*---------------------------------------------------------------------------------------------------------------*/
void QERProgram::setup(
    const std::string& gtpInterface, const std::string& udpInterface,
    const char* qdiscScheduler, std::vector<struct s_fiveQosFlow*> qfis,
    uint64_t seid, gtpUTunnel* gtpTunnel) {
  QdiscHelper qdiscHelper;
  spSkeleton = mpLifeCycle->open();
  initializeMaps();
  mpLifeCycle->load();
  mpLifeCycle->attach();

  setQosFlowsQfis(qfis);
  setPduSessionIds(seid, gtpTunnel);

  setPduSessionClassAttributes(qdiscScheduler);
  setQosFlowsClassesAttributes();
  setPduSessionClassPosition();
  setQosFlowsClassesPositions();

  struct nl_sock* socket = nullptr;
  struct rtnl_link* link = nullptr;

  /*correct the dataplane; it doesn't exist
  and add functions get_socket(), get_link()
  */
  if (!(socket = NetlinkManager::getInstance(gtpInterface).getSocket())) {
    Logger::upf_app().error("Unable to retrieve existing socket");
    exit(EXIT_FAILURE);
  }

  if (!(link = NetlinkManager::getInstance(gtpInterface).getLink())) {
    Logger::upf_app().error("Unable to retrieve existing link");
    exit(EXIT_FAILURE);
  }

  if (!classPduSession) {
    if (!(classPduSession = qdiscHelper.createClass(socket))) {
      Logger::upf_app().error("Unable to create a pduSession Qdisc Class");
      exit(EXIT_FAILURE);
    }
    qdiscHelper.configureParentClass(
        socket, link, classPduSession, pduSessionClassAtt, pduSessionClassPos);
  }

  for (int i = 0; i < sizeof(qfis); i++) {
    struct rtnl_class* qfiFlowClass;
    if (!(qfiFlowClass = qdiscHelper.createClass(socket))) {
      Logger::upf_app().error("Unable to create a QFI_FLOW Qdisc Class");
      // exit(EXIT_FAILURE);
    }
    classesQfiFlows.push_back(qfiFlowClass);
    qdiscHelper.configureLeafClass(
        socket, link, classesQfiFlows[i], qosFlowsClassesAtt[i],
        qosFlowsClassesPos[i]);
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
std::shared_ptr<BPFMap> QERProgram::geGtpUTunnelMap() const {
  return mpGtpUTunnelMap;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<BPFMap> QERProgram::getFilterMap() const {
  return mpFilterMap;
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
void QERProgram::initializeMaps() {
  // Store all maps available in the program.
  mpMaps = std::make_shared<BPFMaps>(mpLifeCycle->getBPFSkeleton()->skeleton);

  // Warning - The name of the map must be the same of the BPF program.
  mpGtpUTunnelMap = std::make_shared<BPFMap>(mpMaps->getMap("m_gtpUTunnel"));
  mpFilterMap     = std::make_shared<BPFMap>(mpMaps->getMap("m_filter"));
  mp5GQoSFlowParamsMap     = std::make_shared<BPFMap>(mpMaps->getMap("m_5g_qos_flow_parameters"));
  mpQoSFlowMap     = std::make_shared<BPFMap>(mpMaps->getMap("m_qos_flow"));
}


/*---------------------------------------------------------------------------------------------------------------*/
void QERProgram::insertValuesIntoMaps() {
  get5GQoSFlowParamsMap()->update(QI_1, FIVE_QI_1, BPF_ANY);
  get5GQoSFlowParamsMap()->update(QI_2, FIVE_QI_2, BPF_ANY);
  get5GQoSFlowParamsMap()->update(QI_3, FIVE_QI_3, BPF_ANY);
  get5GQoSFlowParamsMap()->update(QI_4, FIVE_QI_4, BPF_ANY);
  get5GQoSFlowParamsMap()->update(QI_5, FIVE_QI_5, BPF_ANY);
  get5GQoSFlowParamsMap()->update(QI_6, FIVE_QI_6, BPF_ANY);
  get5GQoSFlowParamsMap()->update(QI_7, FIVE_QI_7, BPF_ANY);
  get5GQoSFlowParamsMap()->update(QI_8, FIVE_QI_8, BPF_ANY);
  get5GQoSFlowParamsMap()->update(QI_9, FIVE_QI_9, BPF_ANY);
  get5GQoSFlowParamsMap()->update(QI_65, FIVE_QI_65, BPF_ANY);
  get5GQoSFlowParamsMap()->update(QI_66, FIVE_QI_66, BPF_ANY);
  get5GQoSFlowParamsMap()->update(QI_67, FIVE_QI_67, BPF_ANY);
  get5GQoSFlowParamsMap()->update(QI_69, FIVE_QI_69, BPF_ANY);
  get5GQoSFlowParamsMap()->update(QI_70, FIVE_QI_70, BPF_ANY);
  get5GQoSFlowParamsMap()->update(QI_71, FIVE_QI_71, BPF_ANY);
  get5GQoSFlowParamsMap()->update(QI_72, FIVE_QI_72, BPF_ANY);
  get5GQoSFlowParamsMap()->update(QI_73, FIVE_QI_73, BPF_ANY);
  get5GQoSFlowParamsMap()->update(QI_74, FIVE_QI_74, BPF_ANY);
  get5GQoSFlowParamsMap()->update(QI_75, FIVE_QI_75, BPF_ANY);
  get5GQoSFlowParamsMap()->update(QI_76, FIVE_QI_76, BPF_ANY);
  get5GQoSFlowParamsMap()->update(QI_79, FIVE_QI_79, BPF_ANY);
  get5GQoSFlowParamsMap()->update(QI_80, FIVE_QI_80, BPF_ANY);
  get5GQoSFlowParamsMap()->update(QI_82, FIVE_QI_82, BPF_ANY);
  get5GQoSFlowParamsMap()->update(QI_83, FIVE_QI_83, BPF_ANY);
  get5GQoSFlowParamsMap()->update(QI_84, FIVE_QI_84, BPF_ANY);
  get5GQoSFlowParamsMap()->update(QI_85, FIVE_QI_85, BPF_ANY);
  get5GQoSFlowParamsMap()->update(QI_86, FIVE_QI_86, BPF_ANY);
}
