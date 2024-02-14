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

#ifndef QUANTUM
#define QUANTUM 1
#endif //QUATUM

#ifndef DEFAULT_CLASS
#define DEFAULT_CLASS 0xffff
#endif //DEFAULT_CLASS

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
const char* UserPlaneComponent::get_root_qdisc_scheduler() const {
  return qdisc_att->scheduler;
}


/*---------------------------------------------------------------------------------------------------------------*/
uint32_t UserPlaneComponent::get_root_qdisc_quantum() const {
  return qdisc_att->quantum;
}


/*---------------------------------------------------------------------------------------------------------------*/
uint32_t UserPlaneComponent::get_root_qdisc_defaultClass() const {
  return qdisc_att->defaultClass;
}


/*---------------------------------------------------------------------------------------------------------------*/
const char* UserPlaneComponent::get_root_class_scheduler() const {
  return class_att->scheduler;
}


/*---------------------------------------------------------------------------------------------------------------*/
uint32_t UserPlaneComponent::get_root_class_rate() const {
  return class_att->rate;
}


/*---------------------------------------------------------------------------------------------------------------*/
uint32_t UserPlaneComponent::get_root_class_ceil() const {
  return class_att->ceil;
}


/*---------------------------------------------------------------------------------------------------------------*/
// Method definition to initialize class_params
void UserPlaneComponent::set_root_class_attributes(std::string interface, const char *scheduler) {
  NicInformationGetter nicInfoGet;
  // Initialize class_att members
  class_att->scheduler = scheduler;
  class_att->rate = nicInfoGet.retrieveRate(interface);
  class_att->ceil = nicInfoGet.retrieveCeil(interface);
  class_att->burst = 0;
  class_att->cburst = 0;
  class_att->priority = 0;
}


/*---------------------------------------------------------------------------------------------------------------*/
// Method definition to initialize qdisc_root_params
void UserPlaneComponent::set_root_qdisc_attributes(const char *scheduler) {
  qdisc_att->scheduler = scheduler;
  qdisc_att->quantum = QUANTUM;
  qdisc_att->defaultClass = DEFAULT_CLASS;
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
  
  QdiscHelper qdiscHelper;

  set_members(pRulesUtilities, gtpInterface, udpInterface);
  set_root_class_attributes(gtpInterface, qdisc_scheduler);
  set_root_qdisc_attributes(qdisc_scheduler);

  SignalHandler::getInstance().enable();
  mpPFCP_Session_LookupProgram->setup();

  // Pass maps to sessionManager.
  mpSessionManager = std::make_shared<SessionManager>();
  
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

  
  if (!(root_class = qdiscHelper.create_class(root_socket))){
    Logger::upf_app().error("Unable to create a Root Qdisc Class");
    exit(EXIT_FAILURE);
  }

  qdiscHelper.configure_root_qdisc(root_socket, link, root_qdisc, qdisc_att);
  qdiscHelper.configure_root_class(root_socket, link, root_class, class_att);
  
}


/*---------------------------------------------------------------------------------------------------------------*/
void UserPlaneComponent::tearDown() {
  QdiscHelper qdiscHelper;
  mpPFCP_Session_LookupProgram->tearDown();
  SessionProgramManager::getInstance().removeAll();
  qdiscHelper.release_netlink_objects(root_socket, root_qdisc);
}
