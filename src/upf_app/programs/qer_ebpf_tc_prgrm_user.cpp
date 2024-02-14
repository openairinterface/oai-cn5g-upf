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
void QERProgram::set_qos_flows_qfis(std::vector<struct qos_flow*> qfis) {
  struct qos_flow *qos_flow;
  for (int i = 0; i < sizeof(qfis); i++){
    qos_flow->qfi = qfis[i]->qfi;
    qos_flow->mbr = qfis[i]->mbr;
    qos_flow->gbr = qfis[i]->gbr;
    
    qos_flows_qfis.push_back(qos_flow);
  }
}

/*---------------------------------------------------------------------------------------------------------------*/
/* 
*  Save the Identifiers of the PDU Session: 
*  Seid,  Teid_ul,  Teid_dl
*/
void QERProgram::set_pdu_session_ids(uint64_t seid) {
  pdu_session->seid = seid;
  struct gtp_u_tunnel gtp_tunnel={};

  if (gtp_tunnel = bpf_map_lookup_elem(&m_gtp_u_tunnel, &seid)){
    pdu_session->teid_ul = gtp_tunnel->teid_ul;
    pdu_session->teid_dl = gtp_tunnel->teid_dl;
  }
  
}


/*---------------------------------------------------------------------------------------------------------------*/
// Method definition to initialize class_params
void QERProgram::set_pdu_session_class_attributes(const char *qdisc_scheduler) {
  // Initialize class_att members
  pdu_session_class_att->scheduler = qdisc_scheduler;
  pdu_session_class_att->rate = -1; //gbr is the correct affectation?
  pdu_session_class_att->ceil = -1; //mbr is the correct affectation?
  pdu_session_class_att->burst = -1;
  pdu_session_class_att->cburst = -1;
  pdu_session_class_att->priority = -1;
}


/*---------------------------------------------------------------------------------------------------------------*/
// Method definition to initialize class_params
void QERProgram::set_qos_flows_classes_attributes() {
  struct class_params* class_att;

  for (int i = 0; i < sizeof(qos_flows_qfis); i++){
    class_att->scheduler = pdu_session_class_att->scheduler;
    class_att->rate[i] = qos_flows_qfis[i]->gbr; // check 5QI table to get this value
    class_att->ceil[i] = qos_flows_qfis[i]->mbr; //check 5QI to get this value
    class_att->burst[i] = -1;
    class_att->cburst[i] = -1;
    class_att->priority[i] = -1;
    
    qos_flows_classes_att->push_back(class_att);
  }
}


/*---------------------------------------------------------------------------------------------------------------*/
// Method definition to set pdu_session class position
void QERProgram::set_pdu_session_class_position() {
  pdu_session_class_pos->parentMaj = 1 ;
  pdu_session_class_pos->parentMin = 0;
  pdu_session_class_pos->childMaj = 1;
  pdu_session_class_pos->childMin = pdu_session->seid && (pdu_session->teid_ul && pdu_session->teid_dl);
}


/*---------------------------------------------------------------------------------------------------------------*/
// Method definition to set pdu_session class position
void QERProgram::set_qos_flows_classes_positions() {
  struct class_position* class_pos;

  class_pos->parentMaj = pdu_session_class_pos->parentMaj;
  class_pos->parentMin = pdu_session_class_pos->parentMin;
  class_pos->childMaj  = pdu_session_class_pos->childMin;
    
  for (int i = 0; i < sizeof(qos_flows_qfis); i++){
    class_pos->childMin = qos_flows_qfis[i];

    qos_flows_classes_pos->push_back();
  }
}


/*---------------------------------------------------------------------------------------------------------------*/
void QERProgram::setup(
    const std::string& gtpInterface, const std::string& udpInterface, const char* qdisc_scheduler, std::vector<uint32_t> qfis, uint64_t seid) {

  QdiscHelper  qdiscHelper;
  spSkeleton = mpLifeCycle->open();
  initializeMaps();
  mpLifeCycle->load();
  mpLifeCycle->attach();

  set_qos_flows_qfis(qfis);
  set_pdu_session_ids(seid);

  set_pdu_session_class_attributes(qdisc_scheduler);
  set_qos_flows_classes_attributes();
  set_pdu_session_class_position();
  set_qos_flows_classes_positions();

  struct nl_sock *socket = nullptr;
  struct rtnl_link *link = nullptr; 

  /*correct the dataplane; it doesn't exist
  and add functions get_socket(), get_link()
  */
  if (!(socket = dataplane.get_socket())){
    Logger::upf_app().error("Unable to retrieve existing socket");
    exit(EXIT_FAILURE);
  }

  if (!(link = dataplane.get_link())){
    Logger::upf_app().error("Unable to retrieve existing link");
    exit(EXIT_FAILURE);
  }

  if (!class_pdu_session){
    if (!(class_pdu_session = qdiscHelper.create_class(socket))){
      Logger::upf_app().error("Unable to create a PDU_SESSION Qdisc Class");
      exit(EXIT_FAILURE);
    }
    qdiscHelper.configure_pdu_session_class(socket, link, class_pdu_session, pdu_session_class_att, pdu_session_class_pos);
  }    
  
  for (int i = 0; i < sizeof(qfis); i++){
    struct rtnl_class* qfi_flow_class;
    if (!(qfi_flow_class = qdiscHelper.create_class(socket))){
    Logger::upf_app().error("Unable to create a QFI_FLOW Qdisc Class");
    //exit(EXIT_FAILURE);
  }
    classes_qfi_flows->push_back();
    qdiscHelper.configure_qos_flow_class(socket, link, classes_qfi_flows[i], qos_flows_classes_att[i], qos_flows_classes_pos[i]);
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
  mpGtpUTunnelMap = std::make_shared<BPFMap>(mpMaps->getMap("m_gtp_u_tunnel"));
  mpFilterMap     = std::make_shared<BPFMap>(mpMaps->getMap("m_filter"));
}


/*---------------------------------------------------------------------------------------------------------------*/
// /*
//  * function that adds a new HTB class and set its parameters
//  */
// int class_add_HTB(struct nl_sock *sock, struct rtnl_link *rtnlLink, 
// 		    uint32_t parentMaj, uint32_t parentMin,
// 		    uint32_t childMaj,  uint32_t childMin, 
// 		    uint64_t rate, uint64_t ceil,
// 		    /* uint32_t burst, uint32_t cburst,*/ 
// 		    uint32_t prio
// )
// {
//     int err;
//     struct rtnl_class *class;
//     //struct rtnl_class *class = (struct rtnl_class *) tc;
//     //create a HTB class 
//     //class = (struct rtnl_class *)rtnl_class_alloc();
//     if (!(class = rtnl_class_alloc())) {
//         printf("Can not allocate class object\n");
//         return 1;
//     }
//     //
//     rtnl_tc_set_link(TC_CAST(class), link);
//     //add a HTB qdisc
//     //printf("Add a new HTB class with 0x%X:0x%X on parent 0x%X:0x%X\n", childMaj, childMin, parentMaj, parentMin);
//     rtnl_tc_set_parent(TC_CAST(class), TC_HANDLE(parentMaj, parentMin));
//     rtnl_tc_set_handle(TC_CAST(class), TC_HANDLE(childMaj, childMin));
//     if ((err = rtnl_tc_set_kind(TC_CAST(class), "htb"))) {
//         printf("Can not set HTB to class\n");
//         return 1;
//     }
//     //printf("set HTB class prio to %u\n", prio);
//     rtnl_htb_set_prio((struct rtnl_class *)class, prio);
//     if (rate) {
// 	//rate=rate/8;
// 	rtnl_htb_set_rate(class, rate);
//     }
//     if (ceil) {
// 	//ceil=ceil/8;
// 	rtnl_htb_set_ceil(class, ceil);
//     }
    
//     if (burst) {
// 	//printf ("Class HTB: set rate burst: %u\n", burst);
//         rtnl_htb_set_rbuffer(class, burst);
//     }
//     if (cburst) {
// 	//printf ("Class HTB: set rate cburst: %u\n", cburst);
//         rtnl_htb_set_cbuffer(class, cburst);
//     }
//     /* Submit request to kernel and wait for response */
//     if ((err = rtnl_class_add(sock, class, NLM_F_CREATE))) {
//         printf("Can not allocate HTB Qdisc\n");
//         return 1;
//     }
//     rtnl_class_put(class);
//     return 0;
// }



/*---------------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------------*/



/*---------------------------------------------------------------------------------------------------------------*/



/*---------------------------------------------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------------------------------------------*/

   
/*---------------------------------------------------------------------------------------------------------------*/    

// struct rtnl_tc *allocate_tc(struct rtnl_tc *tc, struct nl_sock *sock, struct rtnl_qdisc *qdisc){
//     // Allocate a new Traffic Control object
//     tc = rtnl_tc_alloc();

//     if (!tc) {
//         perror("rtnl_tc_alloc");
//         rtnl_qdisc_delete(sock, qdisc);
//         nl_close(sock);
//         nl_socket_free(sock);
//         exit(EXIT_FAILURE);
//     }

//     return tc;
// }

// /*---------------------------------------------------------------------------------------------------------------*/
// void add_qdisc_to_interface(const char *interface, struct nl_sock *sock, struct rtnl_qdisc *qdisc, struct rtnl_tc *tc){
//     // Add the Qdisc to the interface (replace "eth0" with your interface name)
//     if (rtnl_tc_add(sock, tc, NLM_F_CREATE | NLM_F_EXCL, RTM_NEWQDISC, 0, interface) < 0) {
//         perror("rtnl_tc_add");
//         rtnl_tc_free(tc);
//         rtnl_qdisc_delete(sock, qdisc);
//         nl_close(sock);
//         nl_socket_free(sock);
//         exit(EXIT_FAILURE);
//     }
// }

// /*---------------------------------------------------------------------------------------------------------------*/

// // Function to create and configure a Qdisc hierarchy
// void qer_tc::create_configure_hierarchy(struct rtnl_qdisc *root_qdisc, struct nl_sock *sock, qdisc_pdu_to_create, qdisc_qos_flows_to_create) {
    
//     // Create and configure parent classes and their children as needed
//     struct rtnl_qdisc *parent1 = create_parent_class(sock, seid);
//     struct rtnl_qdisc *child1 = create_child_class(sock, parent1, qfi[i]);
//     struct rtnl_qdisc *child2 = create_child_class(sock, parent1, qfi[j]);

//     // Attach parent Qdisc to root Qdisc
//     if (rtnl_qdisc_set_parent(parent1, root_qdisc) < 0) {
//         perror("rtnl_qdisc_set_parent");
//         exit(EXIT_FAILURE);
//     }
// }
// /*---------------------------------------------------------------------------------------------------------------*/
// // Function to create and configure the Qdisc hierarchy
// void qer_tc::create_configure_hierarchy(struct nl_sock *sock, const char *interface, std::vector<std::vector<uint32_t>> child_ids) {
//     // Create and configure parent classes
//     for (size_t i = 0; i < child_ids.size(); ++i) {
//         struct rtnl_qdisc *parent = create_parent_class(sock, interface, i + 1);
//         parent_qdiscs.push_back(parent);

//         // Create and attach child classes
//         std::vector<struct rtnl_qdisc *> children;
//         for (size_t j = 0; j < child_ids[i].size(); ++j) {
//             struct rtnl_qdisc *child = create_child_class(sock, parent, child_ids[i][j]);
//             children.push_back(child);
//         }
//         child_qdiscs.push_back(children);

//         // Attach parent Qdisc to root Qdisc
//         if (rtnl_qdisc_set_parent(parent, root_qdisc) < 0) {
//             perror("rtnl_qdisc_set_parent");
//             exit(EXIT_FAILURE);
//         }
//     }
// }

// /*---------------------------------------------------------------------------------------------------------------*/
// // Function to create a parent class
// struct rtnl_qdisc *qer_tc::create_parent_class(struct nl_sock *sock, const char *interface, uint32_t parent_id) {
//     // Create parent Qdisc
//     struct rtnl_qdisc *parent_qdisc = rtnl_qdisc_alloc();
//     if (!parent_qdisc) {
//         perror("rtnl_qdisc_alloc");
//         exit(EXIT_FAILURE);
//     }
//     // Configure parent Qdisc as needed
//     rtnl_htb_set_rate(parent_qdisc, rate);

//     // Add parent Qdisc to the interface
//     if (rtnl_tc_add(sock, parent_qdisc, NLM_F_CREATE | NLM_F_REPLACE, RTM_NEWQDISC, 0, interface) < 0) {
//         perror("rtnl_tc_add");
//         rtnl_qdisc_free(parent_qdisc);
//         exit(EXIT_FAILURE);
//     }

//     return parent_qdisc;
// }

// /*---------------------------------------------------------------------------------------------------------------*/
// // Function to create a child class
// struct rtnl_qdisc *qer_tc::create_child_class(struct nl_sock *sock, struct rtnl_qdisc *parent, uint32_t child_id) {
//     // Create child Qdisc
//     struct rtnl_qdisc *child_qdisc = rtnl_qdisc_alloc();

//     if (!child_qdisc) {
//         perror("rtnl_qdisc_alloc");
//         exit(EXIT_FAILURE);
//     }
//     // Configure child Qdisc as needed
//     rtnl_htb_set_rate(child_qdisc, rate);

//     // Add child Qdisc to the parent
//     if (rtnl_qdisc_set_parent(child_qdisc, parent) < 0)  {
//         perror("rtnl_qdisc_set_parent");
//         rtnl_qdisc_free(child_qdisc);
//         exit(EXIT_FAILURE);
//     }

//     return child_qdisc;
// }










// #include "qer_tc.hpp"
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <netlink/route/link.h>

// // Constructor
// qer_tc::qer_tc(const char *kind, uint32_t rate) {
//     params.kind = kind;
//     params.rate = rate;
//     // Initialize other parameters as needed
// }
