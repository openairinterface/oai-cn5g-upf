#include "UserPlaneComponent.h"
#include <RulesUtilities.h>
#include <SessionManager.h>
#include <pfcp_session_lookup_ebpf_xdp_prgrm_user.h>
#include <SessionProgramManager.h>
#include <SignalHandler.h>
#include <pfcp_session_pdr_lookup_ebpf_xdp_prgrm_user.h>
#include <utils/LogDefines.h>

/*****************************************************************************************************************/
UserPlaneComponent::UserPlaneComponent()
{
  LOG_FUNC();
// Set new handlers for libbpf.
#ifdef DEBUG_LIBBPF
  libbpf_set_print(UserPlaneComponent::printLibbpfLog);
#endif
}

/*****************************************************************************************************************/
UserPlaneComponent::~UserPlaneComponent()
{
  LOG_FUNC();
  tearDown();
}

/*****************************************************************************************************************/
std::shared_ptr<SessionManager> UserPlaneComponent::getSessionManager() const
{
  LOG_FUNC();
  return mpSessionManager;
}

/*****************************************************************************************************************/
std::shared_ptr<RulesUtilities> UserPlaneComponent::getRulesUtilities() const
{
  LOG_FUNC();
  return mpRulesUtilities;
}

/*****************************************************************************************************************/
std::shared_ptr<PFCP_Session_PDR_Lookup> UserPlaneComponent::getPFCP_Session_PDR_Lookup() const
{
  LOG_FUNC();
  return mpPFCP_Session_PDR_Lookup;
}

/*****************************************************************************************************************/
std::string UserPlaneComponent::getGTPInterface() const
{
  LOG_FUNC();
  return mGTPInterface;
}

/*****************************************************************************************************************/
std::string UserPlaneComponent::getUDPInterface() const
{
  LOG_FUNC();
  return mUDPInterface;
}

/*****************************************************************************************************************/
void UserPlaneComponent::onNewSessionProgram(u_int32_t programId, u_int32_t fileDescriptor)
{
  LOG_FUNC();
  mpPFCP_Session_PDR_Lookup->updateProgramMap(programId, fileDescriptor);
}

/*****************************************************************************************************************/
void UserPlaneComponent::onDestroySessionProgram(u_int32_t programId)
{
  LOG_FUNC();
  mpPFCP_Session_PDR_Lookup->removeProgramMap(programId);
}

/*****************************************************************************************************************/
int UserPlaneComponent::printLibbpfLog(enum libbpf_print_level lvl, const char *fmt, va_list args)
{
  // Do not put LOG_FUNC() here.
  return vfprintf(stderr, fmt, args);
}

/*****************************************************************************************************************/
UserPlaneComponent &UserPlaneComponent::getInstance()
{
  LOG_FUNC();
  static UserPlaneComponent sInstance;
  return sInstance;
}

/*****************************************************************************************************************/
void UserPlaneComponent::setup(
                              std::shared_ptr<RulesUtilities> pRulesUtilities, 
                              const std::string& gtpInterface, 
                              const std::string& udpInterface
                              )
{
  LOG_FUNC();

  mpRulesUtilities = pRulesUtilities;
  mGTPInterface = gtpInterface;
  mUDPInterface = udpInterface;
  mpPFCP_Session_PDR_Lookup = std::make_shared<PFCP_Session_PDR_Lookup>(gtpInterface, udpInterface);

  if(!mpPFCP_Session_PDR_Lookup) {
    LOG_ERROR("Program not initialized");
    throw std::runtime_error("Program not initialized");
  }

  SignalHandler::getInstance().enable();
  mpPFCP_Session_PDR_Lookup->setup();

  // Pass maps to sessionManager.
  mpSessionManager = std::make_shared<SessionManager>();

}

/*****************************************************************************************************************/
void UserPlaneComponent::tearDown()
{
  LOG_FUNC();
  mpPFCP_Session_PDR_Lookup->tearDown();
  SessionProgramManager::getInstance().removeAll();
}
