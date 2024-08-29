#include "UserPlaneComponent.h"
//#include <RulesUtilities.h>
#include <SessionManager.h>
#include <pfcp_session_pdr_lookup_xdp_user.h>
#include <SessionProgramManager.h>
#include <SignalHandler.h>
#include <pfcp_session_lookup_xdp_user.h>
#include "logger.hpp"
#include <helpers/GetNicInformation.hpp>

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
    const std::string& gtpInterface, const std::string& udpInterface) {
  mGTPInterface = gtpInterface;
  mUDPInterface = udpInterface;

  mpPFCP_Session_LookupProgram =
      std::make_shared<PFCP_Session_LookupProgram>(gtpInterface, udpInterface);

  if (!mpPFCP_Session_LookupProgram) {
    Logger::upf_app().error("The eBPF Program is Not Initialized");
    throw std::runtime_error("The eBPF Program is Not Initialized");
  }
}

/*---------------------------------------------------------------------------------------------------------------*/
void UserPlaneComponent::setup(
    const std::string& gtpInterface, const std::string& udpInterface) {
  setMembers(gtpInterface, udpInterface);
  SignalHandler::getInstance().enable();
  mpPFCP_Session_LookupProgram->setup();

  // Pass maps to sessionManager.
  mpSessionManager = std::make_shared<SessionManager>();
}

/*---------------------------------------------------------------------------------------------------------------*/
void UserPlaneComponent::tearDown() {
  mpPFCP_Session_LookupProgram->tearDown();
  SessionProgramManager::getInstance().removeAll();
}
