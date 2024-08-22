#include "UserPlaneComponent.h"
#include <RulesUtilities.h>
#include <SessionManager.h>
#include <NetlinkManager.h>
#include <pfcp_session_pdr_lookup_xdp_user.h>
#include <SessionProgramManager.h>
#include <SignalHandler.h>
#include <pfcp_session_lookup_xdp_user.h>
#include "logger.hpp"
#include <helpers/GetNicInformation.hpp>
#include <helpers/QdiscHelpers.hpp>

#include <netlink/netlink.h>
#include <netlink/route/qdisc.h>
#include <netlink/route/link.h>
#include <netlink/route/qdisc/htb.h>

// #ifndef QUANTUM
// #define QUANTUM 1
// #endif  // QUATUM

// #ifndef DEFAULT_CLASS
// #define DEFAULT_CLASS 30  // 0xffff
// #endif                    // DEFAULT_CLASS

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
// std::shared_ptr<NetlinkManager> UserPlaneComponent::getNetlinkManager() const
// {
//   return mpNetlinkManager;
// }

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
// const char* UserPlaneComponent::getRootQdiscScheduler() const {
//   return qdiscAtt->scheduler;
// }

// /*---------------------------------------------------------------------------------------------------------------*/
// uint32_t UserPlaneComponent::getRootQdiscQuantum() const {
//   return qdiscAtt->quantum;
// }

// /*---------------------------------------------------------------------------------------------------------------*/
// uint32_t UserPlaneComponent::getRootQdiscDefaultClass() const {
//   return qdiscAtt->defaultClass;
// }

// /*---------------------------------------------------------------------------------------------------------------*/
// const char* UserPlaneComponent::getRootClassScheduler() const {
//   return classAtt->scheduler;
// }

// /*---------------------------------------------------------------------------------------------------------------*/
// uint32_t UserPlaneComponent::getRootClassRate() const {
//   return classAtt->rate;
// }

// /*---------------------------------------------------------------------------------------------------------------*/
// uint32_t UserPlaneComponent::getRootClassCeil() const {
//   return classAtt->ceil;
// }

/*---------------------------------------------------------------------------------------------------------------*/
// Method definition to initialize class_params
// void UserPlaneComponent::setRootClassAttributes(
//     std::string interface, const char* scheduler) {
//   NicInformationGetter nicInfoGet;
//   // Initialize classAtt members

//   classAtt = new struct classParams;

//   if (classAtt == nullptr) {
//     Logger::upf_app().error("Failed to allocate memory for classAtt");
//     exit(EXIT_FAILURE);  // or handle the error in some other way
//   }

//   classAtt->scheduler = scheduler;
//   classAtt->rate      = nicInfoGet.retrieveRate(interface);
//   classAtt->ceil      = nicInfoGet.retrieveCeil(interface);
//   classAtt->burst     = 0;
//   classAtt->cburst    = 0;
//   classAtt->priority  = 0;
// }

// /*---------------------------------------------------------------------------------------------------------------*/
// // Method definition to initialize qdisc_root_params
// void UserPlaneComponent::setRootQdiscAttributes(const char* scheduler) {
//   qdiscAtt = new struct qdiscRootParams;

//   if (qdiscAtt == nullptr) {
//     Logger::upf_app().error("Failed to allocate memory for qdiscAtt");
//     exit(EXIT_FAILURE);  // or handle the error in some other way
//   }

//   qdiscAtt->scheduler    = scheduler;
//   qdiscAtt->quantum      = QUANTUM;
//   qdiscAtt->defaultClass = DEFAULT_CLASS;
// }

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
void UserPlaneComponent::setMembers(
    std::shared_ptr<RulesUtilities> pRulesUtilities,
    const std::string& gtpInterface, const std::string& udpInterface) {
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
  setMembers(pRulesUtilities, gtpInterface, udpInterface);
  SignalHandler::getInstance().enable();
  mpPFCP_Session_LookupProgram->setup();

  // Pass maps to sessionManager.
  mpSessionManager = std::make_shared<SessionManager>();
  // mpNetlinkManager =
  // std::make_shared<NetlinkManager>(NetlinkManager::getInstance(gtpInterface));
  // NetlinkManager::getInstance(gtpInterface);
}

/*---------------------------------------------------------------------------------------------------------------*/
// void UserPlaneComponent::setup(
//     std::shared_ptr<RulesUtilities> pRulesUtilities,
//     const std::string& gtpInterface, const std::string& udpInterface /*,
//     const char* qdiscScheduler*/) {
//   // QdiscHelper qdiscHelper;

//   setMembers(pRulesUtilities, gtpInterface, udpInterface);

//   // sock = NetlinkManager::getInstance(mGTPInterface).getSocket();
//   // link = NetlinkManager::getInstance(mGTPInterface).getLink();

//   // setRootQdiscAttributes(qdiscScheduler);
//   // setRootClassAttributes(gtpInterface, qdiscScheduler);

//   // NetlinkManager::getInstance(gtpInterface);

//   // if (!(rootQdisc = qdiscHelper.createQdisc(sock))) {
//   //   Logger::upf_app().error("Unable to create a new Root qdisc");
//   //   exit(EXIT_FAILURE);
//   // }

//   // if (!(rootClass = qdiscHelper.createClass(sock))) {
//   //   Logger::upf_app().error("Unable to create a Root Qdisc Class");
//   //   exit(EXIT_FAILURE);
//   // }

//   // qdiscHelper.configureRootQdisc(sock, link, rootQdisc, qdiscAtt);
//   // qdiscHelper.configureRootClass(sock, link, rootClass, classAtt);

//   SignalHandler::getInstance().enable();
//   mpPFCP_Session_LookupProgram->setup();

//   // Pass maps to sessionManager.
//   mpSessionManager = std::make_shared<SessionManager>();
//   // mpNetlinkManager =
//   //
//   std::make_shared<NetlinkManager>(NetlinkManager::getInstance(gtpInterface));
// }

/*---------------------------------------------------------------------------------------------------------------*/
void UserPlaneComponent::tearDown() {
  QdiscHelper qdiscHelper;

  mpPFCP_Session_LookupProgram->tearDown();
  SessionProgramManager::getInstance().removeAll();
  // qdiscHelper.releaseNetlinkQdisc(sock, rootQdisc);

  // delete qdiscAtt;
  // delete classAtt;
}
