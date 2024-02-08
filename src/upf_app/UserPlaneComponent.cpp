#include "UserPlaneComponent.h"
#include <RulesUtilities.h>
#include <SessionManager.h>
#include <pfcp_session_pdr_lookup_ebpf_xdp_prgrm_user.h>
#include <SessionProgramManager.h>
#include <SignalHandler.h>
#include <pfcp_session_lookup_ebpf_xdp_prgrm_user.h>
#include "logger.hpp"
#include <helpers/GetNicInformation.hpp>
#include <helpers/QdiscHelpers.hpp>

#include <netlink/netlink.h>
#include <netlink/route/qdisc.h>
#include <netlink/route/link.h>
#include <netlink/route/qdisc/htb.h>


 #ifndef QDISC_HTB_SCHEDULER
 #define  QDISC_HTB_SCHEDULER "HTB"
 #endif

/*---------------------------------------------------------------------------------------------------------------*/
UserPlaneComponent::UserPlaneComponent() {
// Set new handlers for libbpf.
#ifdef DEBUG_LIBBPF
  libbpf_set_print(UserPlaneComponent::printLibbpfLog);
#endif
defaultClass = 0xffff;
}

/*---------------------------------------------------------------------------------------------------------------*/
UserPlaneComponent::~UserPlaneComponent() {
  tearDown();
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<SessionManager> UserPlaneComponent::getSessionManager() const {
  return mpSessionManager;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<RulesUtilities> UserPlaneComponent::getRulesUtilities() const {
  return mpRulesUtilities;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::shared_ptr<PFCP_Session_LookupProgram>
UserPlaneComponent::getPFCP_Session_LookupProgram() const {
  return mpPFCP_Session_LookupProgram;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::string UserPlaneComponent::getGTPInterface() const {
  return mGTPInterface;
}

/*---------------------------------------------------------------------------------------------------------------*/
std::string UserPlaneComponent::getUDPInterface() const {
  return mUDPInterface;
}

/*---------------------------------------------------------------------------------------------------------------*/
const char* UserPlaneComponent::getQdiscScheduler() const {
  return mQdiscScheduler;
}

/*---------------------------------------------------------------------------------------------------------------*/
void UserPlaneComponent::onNewSessionProgram(
    u_int32_t programId, u_int32_t fileDescriptor) {
  mpPFCP_Session_LookupProgram->updateProgramMap(programId, fileDescriptor);
}

/*---------------------------------------------------------------------------------------------------------------*/
void UserPlaneComponent::onDestroySessionProgram(u_int32_t programId) {
  mpPFCP_Session_LookupProgram->removeProgramMap(programId);
}

/*---------------------------------------------------------------------------------------------------------------*/
int UserPlaneComponent::printLibbpfLog(
    enum libbpf_print_level lvl, const char* fmt, va_list args) {
  return vfprintf(stderr, fmt, args);
}

/*---------------------------------------------------------------------------------------------------------------*/
UserPlaneComponent& UserPlaneComponent::getInstance() {
  static UserPlaneComponent sInstance;
  return sInstance;
}


/*---------------------------------------------------------------------------------------------------------------*/
void UserPlaneComponent::set_members(std::shared_ptr<RulesUtilities> pRulesUtilities,
    const std::string& gtpInterface, const std::string& udpInterface){
  
  mpRulesUtilities = pRulesUtilities;
  mGTPInterface    = gtpInterface;
  mUDPInterface    = udpInterface;
  mpPFCP_Session_LookupProgram =
      std::make_shared<PFCP_Session_LookupProgram>(gtpInterface, udpInterface);

  if (!mpPFCP_Session_LookupProgram) {
    Logger::upf_app().error("The eBPF Program is Not Initialized");
    throw std::runtime_error("The eBPF Program is Not Initialized");
  }

}

/*---------------------------------------------------------------------------------------------------------------*/
void UserPlaneComponent::setup(
    std::shared_ptr<RulesUtilities> pRulesUtilities,
    const std::string& gtpInterface, const std::string& udpInterface) {

  set_members(pRulesUtilities, gtpInterface, udpInterface);
  SignalHandler::getInstance().enable();
  mpPFCP_Session_LookupProgram->setup();

  // Pass maps to sessionManager.
  mpSessionManager = std::make_shared<SessionManager>();
}

/*---------------------------------------------------------------------------------------------------------------*/
void UserPlaneComponent::setup(
    std::shared_ptr<RulesUtilities> pRulesUtilities,
    const std::string& gtpInterface, const std::string& udpInterface, const char* qdisc_scheduler) {

  set_members(pRulesUtilities, gtpInterface, udpInterface);
  mQdiscScheduler = qdisc_scheduler;

  SignalHandler::getInstance().enable();
  mpPFCP_Session_LookupProgram->setup();

  // Pass maps to sessionManager.
  mpSessionManager = std::make_shared<SessionManager>();
  QdiscHelper qdiscHelper;

  if (!(root_socket = qdiscHelper.create_socket())){
    Logger::upf_app().error("Unable to create a netlink socket");
    exit(EXIT_FAILURE);
  }

  if (!(root_qdisc = qdiscHelper.create_qdisc(root_socket))){
    Logger::upf_app().error("Unable to create a new Root qdisc");
    exit(EXIT_FAILURE);
  }

  if (!(link_cache = qdiscHelper.create_link_cache(root_socket))){
    Logger::upf_app().error("Unable to create a link cache");
    exit(EXIT_FAILURE);
  }

  if (!(link = qdiscHelper.create_link(gtpInterface.c_str(), link_cache, root_socket))){
    Logger::upf_app().error("Unable to create a link");
    exit(EXIT_FAILURE);
  }

  configure_htb_qdisc();
  
  if (!(root_class = qdiscHelper.create_class(root_socket))){
    Logger::upf_app().error("Unable to create a Root Qdisc Class");
    exit(EXIT_FAILURE);
  }

  configure_htb_class();
}


/*---------------------------------------------------------------------------------------------------------------*/
// Method definition to initialize qdisc_att
void UserPlaneComponent::initialize_root_htb_class(std::string interface) {
  NicInformationGetter nicInfoGet;
  // Initialize qdisc_att members
  qdisc_att->scheduler = getQdiscScheduler();
  qdisc_att->rate = nicInfoGet.retrieveRate(interface);
  qdisc_att->ceil = nicInfoGet.retrieveCeil(interface);
  qdisc_att->burst = 0;
  qdisc_att->cburst = 0;
  qdisc_att->quantum = 0;
  qdisc_att->level = 0;
}


// /*---------------------------------------------------------------------------------------------------------------*/
// // Method to create the socket
// void UserPlaneComponent::create_socket(){
//   int err;
//   Logger::upf_app().info("Create a Netlink Socket");
//   if (!(root_socket = nl_socket_alloc())){
//       Logger::upf_app().error("nl_socket_alloc: Unable to allocate netlink socket");
//       exit(EXIT_FAILURE);
//   }

//   // Connect to the socket
//   if ((err = nl_connect(root_socket, NETLINK_ROUTE)) < 0) {
//       Logger::upf_app().error("nl_connect:Unable to connect to the netlink socket");
//       nl_socket_free(root_socket);
//       exit(err);
//   }
// }

// /*---------------------------------------------------------------------------------------------------------------*/
// // Method to create a new HTB qdisc
// void UserPlaneComponent::create_root_qdisc(){
//   Logger::upf_app().info("Create a Qdisc Object");
  
//   if (!(root_qdisc = rtnl_qdisc_alloc())){
//     Logger::upf_app().error("rtnl_qdisc_alloc: Unable to allocate a new qdisc");
//     nl_close(root_socket);
//     nl_socket_free(root_socket);
//     exit(EXIT_FAILURE);
//   }
// }

// /*---------------------------------------------------------------------------------------------------------------*/
// // Method to create a link cache object
// void UserPlaneComponent::create_link_cache(){
//   int err;
//   Logger::upf_app().info("Create a Netlink Link Cache object");
  
//   if ((err = rtnl_link_alloc_cache(root_socket, AF_UNSPEC, &link_cache)) < 0) {
//     Logger::upf_app().error("Unable to allocate link cache: %s\n", nl_geterror(err));
//     nl_socket_free(root_socket);
//     exit(EXIT_FAILURE);
//   }  
// }

// /*---------------------------------------------------------------------------------------------------------------*/
// // Method to create a link object
// void UserPlaneComponent::create_link(const char *iface){
//   Logger::upf_app().info("Create a Netlink Link object");
  
//   if (!(link = rtnl_link_get_by_name(link_cache, iface))) {
//     Logger::upf_app().error("rtnl_link_get_by_name: Interface %s not found\n", iface);
//     nl_socket_free(root_socket);
//     exit(EXIT_FAILURE);
//   }
// }

/*---------------------------------------------------------------------------------------------------------------*/
void UserPlaneComponent::configure_htb_qdisc(){    
  int err;
  Logger::upf_app().info("Set Qdisc Attributes");
  //rtnl_tc_set_ifindex(TC_CAST(qdisc), master_index);
  rtnl_tc_set_link(TC_CAST(root_qdisc), link);
  rtnl_tc_set_parent(TC_CAST(root_qdisc), TC_H_ROOT);

  Logger::upf_app().info("Delete Current Qdisc");
  rtnl_qdisc_delete(root_socket, root_qdisc);
  //rtnl_qdisc_put(qdisc);
    
  Logger::upf_app().info("Add a new HTB Qdisc");
  rtnl_tc_set_handle(TC_CAST(root_qdisc), TC_HANDLE(1,0));
  if ((err = rtnl_tc_set_kind(TC_CAST(root_qdisc), QDISC_HTB_SCHEDULER))) {
    Logger::upf_app().error("rtnl_tc_set_kind: Cannot allocate HTB\n");
    exit(err);
  }
  
  Logger::upf_app().info("Set Default Class for Unclassified Traffic");
  rtnl_htb_set_defcls(root_qdisc, TC_HANDLE(1, defaultClass));
  rtnl_htb_set_rate2quantum(root_qdisc, 1);
  
  /* Submit request to kernel and wait for response */
  Logger::upf_app().info("Submit Qdisc Creation Request to Kernel and Wait for Response");
  if ((err = rtnl_qdisc_add(root_socket, root_qdisc, NLM_F_CREATE))) {
    Logger::upf_app().error("rtnl_qdisc_add: Can not allocate HTB Qdisc\n");
    exit(err);
  }
  
  /* Return the qdisc object to free memory resources */
  rtnl_qdisc_put(root_qdisc);
}

/*---------------------------------------------------------------------------------------------------------------*/

// void UserPlaneComponent::create_root_class(){
//   int err;
//   Logger::upf_app().info("Create a HTB Class");

//   if (!(root_class = (struct rtnl_class *)rtnl_class_alloc())){
//     Logger::upf_app().error("Unable to Allocate Class Object");
//     nl_socket_free(root_socket);
//     exit(EXIT_FAILURE);
//   }
// }

/*---------------------------------------------------------------------------------------------------------------*/
void UserPlaneComponent::configure_htb_class(){
  int err;

  Logger::upf_app().info("Set the Root Class Attributes");
  rtnl_tc_set_link(TC_CAST(root_class), link);
  rtnl_tc_set_parent(TC_CAST(root_class), TC_H_ROOT);
  rtnl_tc_set_handle(TC_CAST(root_class), 1);
  
  if ((err = rtnl_tc_set_kind(TC_CAST(root_class), qdisc_att->scheduler))) {
      Logger::upf_app().error("Unable to set HTB to Class");
      exit(err);
  }

  // rate = rate/8;
	rtnl_htb_set_rate(root_class, qdisc_att->rate);
  
  // ceil = ceil/8;
	rtnl_htb_set_ceil(root_class, qdisc_att->ceil);
  /*
   TODO: - Check if we need burst and cburst values,
         - How to define burst and cburst to appropriate values,
         - Defaults values with the Linux kernel

  rtnl_htb_set_rbuffer(root_class, qdisc_att->burst);
  rtnl_htb_set_cbuffer(root_class, qdisc_att->cburst);
  */  
  /* Submit request to kernel and wait for response */
  Logger::upf_app().info("Submit Class Creation Request to Kernel and Wait for Response");
  if ((err = rtnl_class_add(root_socket, root_class, NLM_F_CREATE))) {
      Logger::upf_app().error("rtnl_class_add: Can not allocate HTB Class\n");
      exit(err);
  }

  rtnl_class_put(root_class);
}

/*---------------------------------------------------------------------------------------------------------------*/
void UserPlaneComponent::tearDown() {
  mpPFCP_Session_LookupProgram->tearDown();
  SessionProgramManager::getInstance().removeAll();
  rtnl_qdisc_delete(root_socket, root_qdisc);
  nl_socket_free(root_socket);
}
