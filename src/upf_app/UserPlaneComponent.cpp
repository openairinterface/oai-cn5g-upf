#include "UserPlaneComponent.h"
#include <RulesUtilities.h>
#include <SessionManager.h>
#include <pfcp_session_lookup_ebpf_xdp_prgrm_user.h>
#include <SessionProgramManager.h>
#include <SignalHandler.h>
#include <pfcp_session_pdr_lookup_ebpf_xdp_prgrm_user.h>
// // #include <utils/LogDefines.h>
#include "logger.hpp"

UserPlaneComponent::UserPlaneComponent()
{
  
// Set new handlers for libbpf.
#ifdef DEBUG_LIBBPF
  libbpf_set_print(UserPlaneComponent::printLibbpfLog);
#endif
}

UserPlaneComponent::~UserPlaneComponent()
{
  
  tearDown();
}

std::shared_ptr<SessionManager> UserPlaneComponent::getSessionManager() const
{
  
  return mpSessionManager;
}

std::shared_ptr<RulesUtilities> UserPlaneComponent::getRulesUtilities() const
{
  
  return mpRulesUtilities;
}

std::shared_ptr<UPFProgram> UserPlaneComponent::getUPFProgram() const
{
  
  return mpUPFProgram;
}

std::string UserPlaneComponent::getGTPInterface() const
{
  
  return mGTPInterface;
}

std::string UserPlaneComponent::getUDPInterface() const
{
  
  return mUDPInterface;
}

void UserPlaneComponent::onNewSessionProgram(u_int32_t programId, u_int32_t fileDescriptor)
{
  
  mpUPFProgram->updateProgramMap(programId, fileDescriptor);
}

void UserPlaneComponent::onDestroySessionProgram(u_int32_t programId)
{
  
  mpUPFProgram->removeProgramMap(programId);
}

int UserPlaneComponent::printLibbpfLog(enum libbpf_print_level lvl, const char *fmt, va_list args)
{
  // Do not put LOG_FUNC() here.
  return vfprintf(stderr, fmt, args);
}

UserPlaneComponent &UserPlaneComponent::getInstance()
{
  
  static UserPlaneComponent sInstance;
  return sInstance;
}

void UserPlaneComponent::setup(std::shared_ptr<RulesUtilities> pRulesUtilities, const std::string& gtpInterface, const std::string& udpInterface)
{
  

  mpRulesUtilities = pRulesUtilities;
  mGTPInterface = gtpInterface;
  mUDPInterface = udpInterface;
  mpUPFProgram = std::make_shared<UPFProgram>(gtpInterface, udpInterface);

  if(!mpUPFProgram) {
    Logger::upf_app().error("Program not initialized");
    throw std::runtime_error("Program not initialized");
  }

  SignalHandler::getInstance().enable();
  mpUPFProgram->setup();

  // Pass maps to sessionManager.
  mpSessionManager = std::make_shared<SessionManager>();

}

void UserPlaneComponent::tearDown()
{
  
  mpUPFProgram->tearDown();
  SessionProgramManager::getInstance().removeAll();
}
