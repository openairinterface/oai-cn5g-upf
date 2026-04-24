/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

/**
 * @file UserPlaneComponent.cpp
 * @brief User Plane Function Component Implementation
 * @author OpenAirInterface
 * @date 2025 / 2026-03
 *
 * Changes (2026-03): Renamed UPF_XDPProgram -> UPF_XDPProgram
 *   in SetMembers() and GetUPF_XDPProgram() -> GetUPF_XDPProgram().
 *
 * Main orchestrator for UPF control plane, managing the BPF tail-call
 * pipeline, PFCP sessions, and network interfaces.
 */

#include "UserPlaneComponent.h"
#include "SessionManager.h"
#include "SessionProgramManager.h"
#include "SignalHandler.h"
#include <upf_xdp_user.h>
#include "logger.hpp"
#include "Configuration.h"
#include "upf_pipeline_config.h"  // PduSessionType, PipelineFeatureFlags, ProgIndex

#include "version_utils.h"
#include "startup_banner.hpp"

//------------------------------------------------------------------------------
// Constructor & Destructor
//------------------------------------------------------------------------------

UserPlaneComponent::UserPlaneComponent() {
#ifdef DEBUG_LIBBPF
  libbpf_set_print(UserPlaneComponent::PrintLibbpfLog);
#endif
}

//------------------------------------------------------------------------------
// Network Configuration
//------------------------------------------------------------------------------

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
// Feature Flag Construction
//------------------------------------------------------------------------------

PipelineFeatureFlags UserPlaneComponent::BuildFeatureFlags() const {
  // g_net_cfg is already populated by BuildNetworkConfig() at this point.
  // All reads go through upf::Is*() / upf::Get*() — no upf_cfg access here.
  PipelineFeatureFlags flags;

  // eBPF Acceleration enabled
  const bool bpf = upf::IsBpfDatapathEnabled();

  // QoS: gate status in XDP + rate shaping in TC
  flags.enable_qer = bpf && upf::IsQosEnabled();

  // Usage Reporting Rules (volume/time measurement)
  flags.enable_urr = bpf && upf::IsUrrEnabled();

  // Buffering Action Rules (DL data notification for idle UEs)
  flags.enable_bar = bpf && upf::IsBarEnabled();

  // Multi-Access Rules (ATSSS steering)
  flags.enable_mar = bpf && upf::IsMarEnabled();

  // Framed Routing support
  flags.enable_framed_routing = bpf && upf::IsFramedRoutingEnabled();

  // PDU session type: select IP or ETH entry programs
  // Config value: "ip" (default) or "ethernet"
  flags.pdu_type = (upf::GetPduSessionType() == "ethernet") ?
                       PduSessionType::Ethernet :
                       PduSessionType::IP;

  return flags;
}

//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Initialization and Teardown
//------------------------------------------------------------------------------

void UserPlaneComponent::SetMembers(
    const std::string& gtp_interface, const std::string& non_gtp_interface) {
  gtp_interface_     = gtp_interface;
  non_gtp_interface_ = non_gtp_interface;

  // Create UPF XDP program (3GPP TS 23.501 Section 6.2.3)
  upf_xdp_program_ =
      std::make_shared<UPF_XDPProgram>(gtp_interface, non_gtp_interface);

  if (!upf_xdp_program_) {
    Logger::upf_app().error("Failed to initialize BPF pipeline program");
    throw std::runtime_error("BPF pipeline initialization failed");
  }

  Logger::upf_app().info("UPF_XDPProgram initialized");
}

//------------------------------------------------------------------------------
void UserPlaneComponent::Setup(
    const std::string& gtp_interface, const std::string& non_gtp_interface) {
  Logger::upf_app().info("Setting up User Plane Component");

  // Step 1: Populate g_net_cfg from upf_cfg.
  //   This is the ONLY place upf_cfg fields are copied into g_net_cfg.
  //   All downstream code (programs, maps, SessionProgramManager) reads
  //   from upf::g_net_cfg via the inline getters in Configuration.h.
  Configuration::BuildNetworkConfig();

  // Step 2: Build feature flags (reads from g_net_cfg, not upf_cfg)
  PipelineFeatureFlags flags = BuildFeatureFlags();

  // // Log what we're about to configure
  // LogPipelineConfig(flags);

  // Initialize interfaces and XDP pipeline program
  SetMembers(gtp_interface, non_gtp_interface);

  // Enable signal handlers for graceful shutdown
  SignalHandler::GetInstance().Enable();

  // Setup the tail-call pipeline:
  //   - Opens skeleton
  //   - Configures maps
  //   - Loads all programs
  //   - Populates PROG_ARRAY based on feature flags
  //   - Links entry programs to N3/N6 interfaces
  upf_xdp_program_->Setup(flags);

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

  // Count loaded features
  int feature_count = 3;  // Core: session_lookup + pdr_match + far
  if (flags.enable_qer) feature_count++;
  if (flags.enable_urr) feature_count++;
  if (flags.enable_bar) feature_count++;
  if (flags.enable_mar) feature_count++;
  if (flags.enable_framed_routing) feature_count++;
  if (flags.pdu_type == PduSessionType::Ethernet) feature_count++;  // broadcast

  const char* pdu_str =
      (flags.pdu_type == PduSessionType::Ethernet) ? "Ethernet" : "IP";

  // Logger::upf_app().info(
  //     "UPF Data Plane setup complete (PDU: %s, QoS: %s, "
  //     "URR: %s, BAR: %s, MAR: %s, pipeline programs: %d)",
  //     pdu_str, flags.enable_qer ? "on" : "off", flags.enable_urr ? "on" :
  //     "off", flags.enable_bar ? "on" : "off", flags.enable_mar ? "on" :
  //     "off", feature_count);

  Logger::upf_app().info("");
  Logger::upf_app().info(" Data Plane setup complete");
  Logger::upf_app().info("  ├─ PDU Session Type  :  %s", pdu_str);
  Logger::upf_app().info(
      "  ├─ QoS Enforcement   :  %s", flags.enable_qer ? "✓ on" : "✗ off");
  Logger::upf_app().info(
      "  ├─ URR Reporting     :  %s", flags.enable_urr ? "✓ on" : "✗ off");
  Logger::upf_app().info(
      "  ├─ BAR Buffering     :  %s", flags.enable_bar ? "✓ on" : "✗ off");
  Logger::upf_app().info(
      "  ├─ MAR Steering      :  %s", flags.enable_mar ? "✓ on" : "✗ off");
  Logger::upf_app().info("  └─ Pipeline slots    :  %d", feature_count);
  Logger::upf_app().info("");

  // Display startup banners
  DisplayConfigSummary();
  DisplayNetworkInterfaces();
  DisplayDataPlaneStatus();
  DisplayPipelineConfig(flags);
  DisplayDataPathArchitecture(flags);

  std::string n3_mode = upf_xdp_program_->GetXdpModeString(upf::GetN3Iface());
  std::string n6_mode = upf_xdp_program_->GetXdpModeString(upf::GetN6Iface());
  size_t total_maps   = upf_xdp_program_->GetTotalMapCount();
  DisplayXdpConfiguration(n3_mode, n6_mode, total_maps);

  DisplayReadyMessage();
}

//------------------------------------------------------------------------------
void UserPlaneComponent::TearDown() {
  Logger::upf_app().info("Tearing down User Plane Component");

  // Remove all sessions from singleton
  SessionProgramManager::GetInstance().RemoveAllSessions();

  // Tear down XDP pipeline
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
std::string UserPlaneComponent::GetNonGTPInterface() const {
  return non_gtp_interface_;
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
