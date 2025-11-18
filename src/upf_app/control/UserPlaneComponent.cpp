/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "UserPlaneComponent.h"
#include <SessionManager.h>
#include <SessionProgramManager.h>
#include <SignalHandler.h>
#include <upf_xdp_user.h>
#include "logger.hpp"
#include <helpers/GetNicInformation.hpp>

#include "upf_config.hpp"
using namespace oai::config;
extern upf_config upf_cfg;

//---------------------------------------------------------------------------------------------------------------
UserPlaneComponent::UserPlaneComponent() {
// Set new handlers for libbpf.
#ifdef DEBUG_LIBBPF
  libbpf_set_print(UserPlaneComponent::printLibbpfLog);
#endif
}

//---------------------------------------------------------------------------------------------------------------
UserPlaneComponent::~UserPlaneComponent() {
  tearDown();
}

//---------------------------------------------------------------------------------------------------------------
std::shared_ptr<SessionManager> UserPlaneComponent::getSessionManager() const {
  return mpSessionManager;
}

//---------------------------------------------------------------------------------------------------------------
std::shared_ptr<UPF_XDPProgram> UserPlaneComponent::getUPF_XDPProgram() const {
  return mpUPF_XDPProgram;
}

//---------------------------------------------------------------------------------------------------------------
std::string UserPlaneComponent::getGTPInterface() const {
  return mGTPInterface;
}

//---------------------------------------------------------------------------------------------------------------
std::string UserPlaneComponent::getUDPInterface() const {
  return mUDPInterface;
}

//---------------------------------------------------------------------------------------------------------------
void UserPlaneComponent::onNewSessionProgram(
    u_int32_t programId, u_int32_t fileDescriptor) {
  // mpUPF_XDPProgram->updateProgramMap(programId, fileDescriptor);
}

//---------------------------------------------------------------------------------------------------------------
void UserPlaneComponent::onDestroySessionProgram(uint32_t programId) {
  mpUPF_XDPProgram->removeProgramMap(programId);
}

//---------------------------------------------------------------------------------------------------------------
int UserPlaneComponent::printLibbpfLog(
    enum libbpf_print_level lvl, const char* fmt, va_list args) {
  return vfprintf(stderr, fmt, args);
}

//---------------------------------------------------------------------------------------------------------------
UserPlaneComponent& UserPlaneComponent::getInstance() {
  static UserPlaneComponent sInstance;
  return sInstance;
}

//---------------------------------------------------------------------------------------------------------------
void UserPlaneComponent::setMembers(
    const std::string& gtpInterface, const std::string& udpInterface) {
  mGTPInterface = gtpInterface;
  mUDPInterface = udpInterface;

  mpUPF_XDPProgram =
      std::make_shared<UPF_XDPProgram>(gtpInterface, udpInterface, upf_cfg);

  if (!mpUPF_XDPProgram) {
    Logger::upf_app().error("The eBPF Program is Not Initialized");
    throw std::runtime_error("The eBPF Program is Not Initialized");
  }

  mpFARTCProgram = std::make_shared<FARTCProgram>();
  if (!mpFARTCProgram) {
    Logger::upf_app().error("The eBPF Program is Not Initialized");
    throw std::runtime_error("The eBPF Program is Not Initialized");
  }
}

//---------------------------------------------------------------------------------------------------------------
void UserPlaneComponent::setup(
    const std::string& gtpInterface, const std::string& udpInterface) {
  const bool isQosEnabled = upf_cfg.enable_bpf_datapath && upf_cfg.enable_qos;
  const bool isEthPduEnabled =
      upf_cfg.enable_bpf_datapath && upf_cfg.enable_eth_pdu;

  setMembers(gtpInterface, udpInterface);
  SignalHandler::getInstance().enable();

  mpUPF_XDPProgram->setup(isQosEnabled);

  if (isEthPduEnabled) {
    mpFARTCProgram->setup();
  }

  // Pass maps to sessionManager.
  mpSessionManager = std::make_shared<SessionManager>();
}

//---------------------------------------------------------------------------------------------------------------
void UserPlaneComponent::tearDown() {
  mpUPF_XDPProgram->tearDown();
  SessionProgramManager::getInstance().removeAll();
}
