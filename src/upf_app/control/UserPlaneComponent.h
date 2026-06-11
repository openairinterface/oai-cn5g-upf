/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/**
 * @file UserPlaneComponent.h
 * @brief Main User Plane Function Component
 *
 * This module is the main entry point and orchestrator for the User Plane
 * Function (UPF) control plane. It coordinates session management, BPF/XDP
 * programs, and network interfaces.
 *
 * Key 3GPP References:
 * - 3GPP TS 23.501: System architecture for the 5G System
 * - 3GPP TS 29.244: Interface between Control Plane and User Plane nodes
 * - 3GPP TS 23.501 Section 6.2.3: User Plane Function (UPF)
 * - 3GPP TS 29.244 Section 4: PFCP Protocol
 */

#ifndef USER_PLANE_COMPONENT_H_
#define USER_PLANE_COMPONENT_H_

#include <bpf/libbpf.h>
#include <memory>
#include <string>
#include "observer/SessionObserver.h"  // For ISessionObserver interface

// Pipeline config types (PduSessionType, PipelineFeatureFlags, ProgIndex)
// Included directly so control/ builds without needing the XDP skeleton.
#include "upf_pipeline_config.h"

// Forward declarations
class SessionManager;
class UPF_XDPProgram;

/**
 * @class UserPlaneComponent
 * @brief Main orchestrator for UPF user plane data path
 *
 * The UserPlaneComponent manages the complete user plane stack:
 *   - BPF tail-call pipeline lifecycle for modular packet processing
 *   - PFCP session management (3GPP TS 29.244)
 *   - Network interface configuration (N3, N6)
 *   - Feature flag management (QER, URR, BAR, MAR, ETH PDU)
 *   - Signal handling for graceful shutdown
 *
 * Configuration (from YAML):
 *   - enable_bpf_datapath: Master switch for BPF acceleration
 *   - enable_qer: QER enforcement (XDP gate + TC rate shaping)
 *   - enable_urr: Usage reporting (volume/time measurement)
 *   - enable_bar: Buffering action (DL data notification)
 *   - enable_mar: Multi-access steering (ATSSS)
 *   - enable_framed_routing: Framed route support
 *   - pdu_session_type: "ip" or "ethernet" (entry program selection)
 *
 * Thread Safety: This class is thread-safe for observer callbacks.
 *
 * @note Implements ISessionObserver to receive session program events
 * @note Follows Google C++ Style Guide
 */
class UserPlaneComponent : public ISessionObserver {
 public:
  /**
   * @brief Destructor - automatically tears down resources
   */
  virtual ~UserPlaneComponent();

  /**
   * @brief Get singleton instance
   *
   * @return Reference to singleton instance
   *
   * @deprecated Use dependency injection in new code
   * @note Singleton pattern maintained for backward compatibility
   */
  static UserPlaneComponent& GetInstance();

  /**
   * @brief Setup user plane component with network interfaces
   *
   * Initializes the complete pipeline:
   *   1. N3 interface for GTP-U traffic (3GPP TS 29.281)
   *   2. N6 interface for data network traffic
   *   3. Reads feature flags from upf::g_net_cfg
   *   4. Creates UPF_XDPProgram with tail-call pipeline
   *   5. Loads and attaches BPF programs based on config
   *   6. Populates PROG_ARRAY for enabled features
   *   7. Creates SessionManager for PFCP sessions
   *   8. Logs pipeline configuration summary
   *
   * @param gtp_interface N3 interface name (e.g., "eth0")
   * @param udp_interface N6 interface name (e.g., "eth1")
   *
   * @throws std::runtime_error if setup fails
   *
   * @see 3GPP TS 23.501 Section 5.8.2 - UPF interfaces
   */
  void Setup(
      const std::string& gtp_interface, const std::string& udp_interface);

  /**
   * @brief Set component members before full setup
   *
   * Configures interface names and creates XDP program instance.
   * Called internally by Setup().
   *
   * @param gtp_interface N3 interface name
   * @param non_gtp_interface N6 interface name
   */
  void SetMembers(
      const std::string& gtp_interface, const std::string& non_gtp_interface);

  /**
   * @brief Tear down user plane component and cleanup resources
   *
   * Performs graceful shutdown:
   *   - Removes all active sessions
   *   - Unloads BPF tail-call pipeline
   *   - Releases network interfaces
   */
  void TearDown();

  /**
   * @brief Get session manager instance
   *
   * @return Shared pointer to session manager
   *
   * @note Session manager handles PFCP session lifecycle (3GPP TS 29.244)
   */
  std::shared_ptr<SessionManager> GetSessionManager() const;

  /**
   * @brief Get BPF data plane manager instance
   *
   * @return Shared pointer to UPF_XDPProgram
   */
  std::shared_ptr<UPF_XDPProgram> GetUPF_XDPProgram() const;

  /**
   * @brief Get N3 (GTP-U) interface name
   *
   * @return GTP interface name
   *
   * @see 3GPP TS 23.501 Section 5.8.2.2 - N3 Interface
   */
  std::string GetGTPInterface() const;

  /**
   * @brief Get N6 (Data Network) interface name
   *
   * @return UDP interface name
   *
   * @see 3GPP TS 23.501 Section 5.8.2.3 - N6 Interface
   */
  std::string GetNonGTPInterface() const;

  void PrintStartupSummary();

  // ==========================================================================
  // ISessionObserver Implementation
  // ==========================================================================

  /**
   * @brief Callback when new session program is created
   *
   * Called by SessionProgramManager when a new BPF program is created.
   * Updates XDP program maps accordingly.
   *
   * @param program_id Program identifier
   * @param file_descriptor BPF program file descriptor
   */
  void OnNewSessionProgram(
      uint32_t program_id, uint32_t file_descriptor) override;

  /**
   * @brief Callback when session program is destroyed
   *
   * Called by SessionProgramManager when a BPF program is removed.
   * Cleans up XDP program maps.
   *
   * @param program_id Program identifier to destroy
   */
  void OnDestroySessionProgram(uint32_t program_id) override;

  /**
   * @brief Callback when session program is updated
   *
   * Called by SessionProgramManager when a BPF program is modified.
   * Updates XDP program maps with new configuration.
   *
   * @param program_id Program identifier
   * @param file_descriptor New BPF program file descriptor
   */
  void OnUpdateSessionProgram(
      uint32_t program_id, uint32_t file_descriptor) override;

 private:
  /**
   * @brief Private constructor for singleton pattern
   */
  UserPlaneComponent();

  /**
   * @brief Build PipelineFeatureFlags from upf::g_net_cfg
   *
   * Reads all enable_* and pdu_session_type fields from config
   * and constructs the feature flags structure.
   *
   * @return PipelineFeatureFlags populated from config
   */
  /**
   * @brief Build PipelineFeatureFlags from upf::g_net_cfg
   *
   * Must be called after Configuration::BuildNetworkConfig().
   */
  PipelineFeatureFlags BuildFeatureFlags() const;

  //   /**
  //    * @brief Log pipeline feature configuration summary
  //    *
  //    * Prints which features are enabled/disabled and which
  //    * entry programs are selected (IP vs ETH).
  //    *
  //    * @param flags Current feature flags
  //    */
  //   void LogPipelineConfig(const PipelineFeatureFlags& flags) const;

  /**
   * @brief Log callback for libbpf
   *
   * @param lvl Log level
   * @param fmt Format string
   * @param args Variable arguments
   * @return Number of characters printed
   */
  static int PrintLibbpfLog(
      enum libbpf_print_level lvl, const char* fmt, va_list args);

  // ==========================================================================
  // Member Variables
  // ==========================================================================

  /// Session manager for PFCP session lifecycle
  std::shared_ptr<SessionManager> session_manager_;

  /// BPF data plane manager (entry programs + shared map ownership)
  std::shared_ptr<UPF_XDPProgram> upf_xdp_program_;

  /// N3 GTP-U interface name
  std::string gtp_interface_;

  /// N6 Data Network interface name
  std::string non_gtp_interface_;
};

#endif  // USER_PLANE_COMPONENT_H_
