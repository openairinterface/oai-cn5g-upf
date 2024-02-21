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
//#include "gtpUTunnel_key.h"
//#include "qer_maps.h"

/*---------------------------------------------------------------------------------------------------------------*/
QERProgram::QERProgram(
    const std::string& gtpInterface, const std::string& udpInterface)
    : mGTPInterface(gtpInterface), mUDPInterface(udpInterface) {
  mpLifeCycle = std::make_shared<QERProgramLifeCycle>(
      qer_ebpf_tc_prgrm_kernel_c__open,
      qer_ebpf_tc_prgrm_kernel_c__load,
      qer_ebpf_tc_prgrm_kernel_c__attach,
      qer_ebpf_tc_prgrm_kernel_c__destroy);
}


/*---------------------------------------------------------------------------------------------------------------*/
QERProgram::~QERProgram() {}


/*---------------------------------------------------------------------------------------------------------------*/
void QERProgram::setup() {
  spSkeleton = mpLifeCycle->open();
  initializeMaps();
  mpLifeCycle->load();
  mpLifeCycle->attach();
}


/*---------------------------------------------------------------------------------------------------------------*/
/* 
*  Save the different QFI values for all QoS 
*  Flows belonging to the same PDU Session
*/
void QERProgram::setQosFlowsQfis(std::vector<struct qosFlow*> qfis) {
  struct qosFlow *qosFlow;
  for (int i = 0; i < sizeof(qfis); i++){
    qosFlow->qfi = qfis[i]->qfi;
    qosFlow->mbr = qfis[i]->mbr;
    qosFlow->gbr = qfis[i]->gbr;
    
    qosFlowsQfis.push_back(qosFlow);
  }
}

/*---------------------------------------------------------------------------------------------------------------*/
/* 
*  Save the Identifiers of the PDU Session: 
*  Seid,  teidUl,  teidDl
*/
void QERProgram::setPduSessionIds(uint64_t seid, struct gtpUTunnel *gtpTunnel) {
  pduSession->seid = seid;
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
void QERProgram::setPduSessionClassAttributes(const char *qdiscScheduler) {
  // Initialize classAtt members
  pduSessionClassAtt->scheduler = qdiscScheduler;
  pduSessionClassAtt->rate = -1; //gbr is the correct affectation?
  pduSessionClassAtt->ceil = -1; //mbr is the correct affectation?
  pduSessionClassAtt->burst = -1;
  pduSessionClassAtt->cburst = -1;
  pduSessionClassAtt->priority = -1;
}


/*---------------------------------------------------------------------------------------------------------------*/
// Method definition to initialize class_params
void QERProgram::setQosFlowsClassesAttributes() {
  struct classParams* classAtt;

  for (int i = 0; i < sizeof(qosFlowsQfis); i++){
    classAtt->scheduler = pduSessionClassAtt->scheduler;
    classAtt->rate = qosFlowsQfis[i]->gbr; // check 5QI table to get this value
    classAtt->ceil = qosFlowsQfis[i]->mbr; //check 5QI to get this value
    classAtt->burst = -1;
    classAtt->cburst = -1;
    classAtt->priority = -1;
    
    qosFlowsClassesAtt.push_back(classAtt);
  }
}


/*---------------------------------------------------------------------------------------------------------------*/
// Method definition to set pduSession class position
void QERProgram::setPduSessionClassPosition() {
  pduSessionClassPos->parentMaj = 1 ;
  pduSessionClassPos->parentMin = 0;
  pduSessionClassPos->childMaj = 1;
  pduSessionClassPos->childMin = pduSession->seid && (pduSession->teidUl && pduSession->teidDl);
}


/*---------------------------------------------------------------------------------------------------------------*/
// Method definition to set pduSession class position
void QERProgram::setQosFlowsClassesPositions() {
  struct classPosition* classPos;

  classPos->parentMaj = pduSessionClassPos->parentMaj;
  classPos->parentMin = pduSessionClassPos->parentMin;
  classPos->childMaj  = pduSessionClassPos->childMin;
    
  for (int i = 0; i < sizeof(qosFlowsQfis); i++){
    classPos->childMin = qosFlowsQfis[i]->qfi;

    qosFlowsClassesPos.push_back(classPos);
  }
}


/*---------------------------------------------------------------------------------------------------------------*/
void QERProgram::setup(
    const std::string& gtpInterface, 
    const std::string& udpInterface, 
    const char* qdiscScheduler, 
    std::vector<struct qosFlow*> qfis, 
    uint64_t seid, 
    gtpUTunnel *gtpTunnel) {

  QdiscHelper  qdiscHelper;
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

  struct nl_sock *socket = nullptr;
  struct rtnl_link *link = nullptr; 

  /*correct the dataplane; it doesn't exist
  and add functions get_socket(), get_link()
  */
  if (!(socket = NetlinkManager::getInstance(gtpInterface).getSocket())){
    Logger::upf_app().error("Unable to retrieve existing socket");
    exit(EXIT_FAILURE);
  }

  if (!(link = NetlinkManager::getInstance(gtpInterface).getLink())){
    Logger::upf_app().error("Unable to retrieve existing link");
    exit(EXIT_FAILURE);
  }

  if (!classPduSession){
    if (!(classPduSession = qdiscHelper.createClass(socket))){
      Logger::upf_app().error("Unable to create a pduSession Qdisc Class");
      exit(EXIT_FAILURE);
    }
    qdiscHelper.configureParentClass(socket, link, classPduSession, pduSessionClassAtt, pduSessionClassPos);    
  }    
  
  for (int i = 0; i < sizeof(qfis); i++){
    struct rtnl_class* qfiFlowClass;
    if (!(qfiFlowClass = qdiscHelper.createClass(socket))){
    Logger::upf_app().error("Unable to create a QFI_FLOW Qdisc Class");
    //exit(EXIT_FAILURE);
  }
    classesQfiFlows.push_back(qfiFlowClass);
    qdiscHelper.configureLeafClass(socket, link, classesQfiFlows[i], qosFlowsClassesAtt[i], qosFlowsClassesPos[i]);
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
void QERProgram::initializeMaps() {
  // Store all maps available in the program.
  mpMaps = std::make_shared<BPFMaps>(mpLifeCycle->getBPFSkeleton()->skeleton);

  // Warning - The name of the map must be the same of the BPF program.
  mpGtpUTunnelMap = std::make_shared<BPFMap>(mpMaps->getMap("m_gtpUTunnel"));
  mpFilterMap     = std::make_shared<BPFMap>(mpMaps->getMap("m_filter"));
}