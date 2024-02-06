#include "UserPlaneComponent.h"
#include <RulesUtilities.h>
#include <SessionManager.h>
#include <pfcp_session_pdr_lookup_ebpf_xdp_prgrm_user.h>
#include <SessionProgramManager.h>
#include <SignalHandler.h>
#include <pfcp_session_lookup_ebpf_xdp_prgrm_user.h>
#include "logger.hpp"
#include <helpers/GetNicInformation.hpp>

#include <netlink/netlink.h>
#include <netlink/route/qdisc.h>
#include <netlink/route/link.h>
#include <netlink/route/qdisc/htb.h>


#ifndef QDISC_HTB_SCHEDULER
#define  QDISC_HTB_SCHEDULER HTB
#endif

/*---------------------------------------------------------------------------------------------------------------*/
UserPlaneComponent::UserPlaneComponent() {
// Set new handlers for libbpf.
#ifdef DEBUG_LIBBPF
  libbpf_set_print(UserPlaneComponent::printLibbpfLog);
#endif
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
  
  qdisc_att = new struct qdisc_params;   
}

/*---------------------------------------------------------------------------------------------------------------*/
// Method to create the root qdisc
struct rtnl_qdisc* UserPlaneComponent::create_qdisc(struct nl_sock *sock){
    // Allocate a new Qdisc object
    struct rtnl_qdisc *qdisc = rtnl_qdisc_alloc();

    if (!qdisc) {
        perror("rtnl_qdisc_alloc");
        nl_close(sock);
        nl_socket_free(sock);
        exit(EXIT_FAILURE);
    }

    return qdisc;
}

/*---------------------------------------------------------------------------------------------------------------*/
// Method definition to initialize qdisc_att
void UserPlaneComponent::initializeQdisc(std::string interface) {
  NicInformationGetter nicInfoGet;
  // Initialize qdisc_att members
  qdisc_att->scheduler = getQdiscScheduler();
  qdisc_att->rate = nicInfoGet.retrieveRate(interface);
  qdisc_att->ceil = nicInfoGet.retrieveCeil(interface);
  qdisc_att->rate_buffer = 0;
  qdisc_att->ceil_buffer = 0;
  qdisc_att->quantum = 0;
  qdisc_att->level = 0;
}


/*---------------------------------------------------------------------------------------------------------------*/
struct rtnl_qdisc* UserPlaneComponent::configure_qdisc(struct rtnl_qdisc *qdisc, struct rtnl_class *htb_class){    
  // Set Qdisc attributes
  rtnl_tc_set_kind(TC_CAST(qdisc), qdisc_att->scheduler);
  if (strcmp(qdisc_att->scheduler, QDISC_HTB_SCHEDULER) == 0) {
    rtnl_htb_set_rate(htb_class, qdisc_att->rate); // Set Physical capacity
    rtnl_htb_set_rbuffer(htb_class, qdisc_att->rate_buffer);
    rtnl_htb_set_cbuffer(htb_class, qdisc_att->ceil_buffer);
    rtnl_htb_set_quantum(htb_class, qdisc_att->quantum);
    rtnl_htb_set_level(htb_class, qdisc_att->level);
  }    
  // Set additional Qdisc attributes as needed

  return qdisc; 
}

/*---------------------------------------------------------------------------------------------------------------*/
void UserPlaneComponent::tearDown() {
  mpPFCP_Session_LookupProgram->tearDown();
  SessionProgramManager::getInstance().removeAll();
}
