/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/**
 * @file UserPlaneComponent.cpp
 * @brief User Plane Function Component Implementation
 *
 * Main orchestrator for UPF control plane, managing BPF/XDP programs,
 * PFCP sessions, and network interfaces according to 3GPP TS 23.501.
 */

#include "UserPlaneComponent.h"
#include "SessionManager.h"
#include "SessionProgramManager.h"
#include "SignalHandler.h"
#include <upf_xdp_user.h>
#include <far_tc_user.h>
#include "logger.hpp"
#include "upf_config.hpp"

#include "version_utils.h"
#include "startup_banner.hpp"

using namespace oai::config;
extern upf_config upf_cfg;

//------------------------------------------------------------------------------
// Constructor & Destructor
//------------------------------------------------------------------------------

UserPlaneComponent::UserPlaneComponent() {
#ifdef DEBUG_LIBBPF
  libbpf_set_print(UserPlaneComponent::PrintLibbpfLog);
#endif
}

//------------------------------------------------------------------------------
UserPlaneComponent::~UserPlaneComponent() {
  TearDown();
}

//------------------------------------------------------------------------------
// Singleton Access
//------------------------------------------------------------------------------

UserPlaneComponent& UserPlaneComponent::GetInstance() {
  static UserPlaneComponent instance;
  return instance;
}

//------------------------------------------------------------------------------
// Initialization and Teardown
//------------------------------------------------------------------------------

void UserPlaneComponent::SetMembers(
    const std::string& gtp_interface, const std::string& udp_interface) {
  gtp_interface_ = gtp_interface;
  udp_interface_ = udp_interface;

  // Create UPF XDP program (3GPP TS 23.501 Section 6.2.3)
  upf_xdp_program_ =
      std::make_shared<UPF_XDPProgram>(gtp_interface, udp_interface, upf_cfg);

  if (!upf_xdp_program_) {
    Logger::upf_app().error("Failed to initialize eBPF program");
    throw std::runtime_error("eBPF program initialization failed");
  }

  Logger::upf_app().info(
      "UPF XDP program initialized (N3: %s, N6: %s)", gtp_interface.c_str(),
      udp_interface.c_str());
}

//------------------------------------------------------------------------------
void UserPlaneComponent::Setup(
    const std::string& gtp_interface, const std::string& udp_interface) {
  Logger::upf_app().info("Setting up User Plane Component");

  // QoS enablement check
  const bool is_qos_enabled = upf_cfg.enable_bpf_datapath && upf_cfg.enable_qos;

  // Initialize interfaces and XDP program
  SetMembers(gtp_interface, udp_interface);

  // Enable signal handlers for graceful shutdown
  SignalHandler::GetInstance().Enable();

  // Setup XDP program with QoS configuration
  upf_xdp_program_->Setup(is_qos_enabled);

  // Get SessionProgramManager singleton
  SessionProgramManager& session_program_manager =
      SessionProgramManager::GetInstance();

  // Set this component as observer for session events
  session_program_manager.SetSessionObserver(this);

  // Create non-owning shared_ptr to singleton (deleter does nothing)
  std::shared_ptr<SessionProgramManager> session_prgm_mngr(
      &session_program_manager, [](SessionProgramManager*) {}
      // Empty deleter - don't delete singleton!
  );

  // Create SessionManager with proper dependencies
  session_manager_ = std::make_shared<SessionManager>(session_prgm_mngr);

  if (!session_manager_) {
    Logger::upf_app().error("Failed to create SessionManager");
    throw std::runtime_error("SessionManager creation failed");
  }

  // Initialize global variable for pfcp_switch.cpp
  extern std::shared_ptr<SessionManager> session_manager;
  session_manager = session_manager_;

  Logger::upf_app().info("Session Manager initialized");

  Logger::upf_app().info(
      "UPF Data Plane setup complete (QoS: %s)",
      is_qos_enabled ? "enabled" : "disabled");

  DisplayConfigSummary(upf_cfg);

  DisplayNetworkInterfaces(upf_cfg);
  DisplayDataPlaneStatus(upf_cfg);
  std::string n3_mode = upf_xdp_program_->GetXdpModeString(upf_cfg.n3.if_name);
  std::string n6_mode = upf_xdp_program_->GetXdpModeString(upf_cfg.n6.if_name);
  size_t total_maps   = upf_xdp_program_->GetMapCount();
  DisplayXdpConfiguration(upf_cfg, n3_mode, n6_mode, total_maps);

  DisplayReadyMessage();
}

//------------------------------------------------------------------------------
void UserPlaneComponent::TearDown() {
  Logger::upf_app().info("Tearing down User Plane Component");

  // Remove all sessions from singleton
  SessionProgramManager::GetInstance().RemoveAllSessions();

  // Tear down XDP program
  if (upf_xdp_program_) {
    upf_xdp_program_->TearDown();
  }

  // Reset session manager
  if (session_manager_) {
    session_manager_.reset();
  }

  Logger::upf_app().info("User Plane Component teardown completed");
}

//------------------------------------------------------------------------------
// Getters
//------------------------------------------------------------------------------

std::shared_ptr<SessionManager> UserPlaneComponent::GetSessionManager() const {
  return session_manager_;
}

//------------------------------------------------------------------------------
std::shared_ptr<UPF_XDPProgram> UserPlaneComponent::GetUPF_XDPProgram() const {
  return upf_xdp_program_;
}

//------------------------------------------------------------------------------
std::string UserPlaneComponent::GetGTPInterface() const {
  return gtp_interface_;
}

//------------------------------------------------------------------------------
std::string UserPlaneComponent::GetUDPInterface() const {
  return udp_interface_;
}

//------------------------------------------------------------------------------
// ISessionObserver Implementation
//------------------------------------------------------------------------------

void UserPlaneComponent::OnNewSessionProgram(
    uint32_t program_id, uint32_t file_descriptor) {
  // Update program map if needed
  // upf_xdp_program_->updateProgramMap(program_id, file_descriptor);
  Logger::upf_app().debug(
      "New session program: ID=%u FD=%u", program_id, file_descriptor);
}

//------------------------------------------------------------------------------
void UserPlaneComponent::OnDestroySessionProgram(uint32_t program_id) {
  if (upf_xdp_program_) {
    upf_xdp_program_->RemoveProgramMap(program_id);
  }
  Logger::upf_app().debug("Destroyed session program: ID=%u", program_id);
}

//------------------------------------------------------------------------------
void UserPlaneComponent::OnUpdateSessionProgram(
    uint32_t program_id, uint32_t file_descriptor) {
  // Update program map if needed
  Logger::upf_app().debug(
      "Updated session program: ID=%u FD=%u", program_id, file_descriptor);
}

//------------------------------------------------------------------------------
// Static Helpers
//------------------------------------------------------------------------------

int UserPlaneComponent::PrintLibbpfLog(
    enum libbpf_print_level lvl, const char* fmt, va_list args) {
  return vfprintf(stderr, fmt, args);
}
