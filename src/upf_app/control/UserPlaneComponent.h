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

// Forward declarations
class SessionManager;
class UPF_XDPProgram;

/**
 * @class UserPlaneComponent
 * @brief Main orchestrator for UPF user plane data path
 *
 * The UserPlaneComponent manages the complete user plane stack:
 * - BPF/XDP program lifecycle for packet processing
 * - PFCP session management (3GPP TS 29.244)
 * - Network interface configuration (N3, N6)
 * - Signal handling for graceful shutdown
 *
 * Architecture:
 * - N3 Interface: Connection to gNodeB (3GPP TS 23.501 Section 5.8.2.2)
 * - N6 Interface: Connection to Data Network (3GPP TS 23.501 Section 5.8.2.3)
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
   * Initializes:
   * - N3 interface for GTP-U traffic (3GPP TS 29.281)
   * - N6 interface for data network traffic
   * - BPF/XDP programs for packet processing
   * - Session manager for PFCP sessions
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
   * @param udp_interface N6 interface name
   */
  void SetMembers(
      const std::string& gtp_interface, const std::string& udp_interface);

  /**
   * @brief Tear down user plane component and cleanup resources
   *
   * Performs graceful shutdown:
   * - Removes all active sessions
   * - Unloads BPF/XDP programs
   * - Releases network interfaces
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
   * @brief Get UPF XDP program instance
   *
   * @return Shared pointer to XDP program
   *
   * @note XDP program is the entry point for packet processing
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
  std::string GetUDPInterface() const;

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

  /// UPF XDP program (BPF program entry point)
  std::shared_ptr<UPF_XDPProgram> upf_xdp_program_;

  /// N3 GTP-U interface name
  std::string gtp_interface_;

  /// N6 Data Network interface name
  std::string udp_interface_;
};

#endif  // USER_PLANE_COMPONENT_H_
