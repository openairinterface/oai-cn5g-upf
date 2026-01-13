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
 * @file SessionManager.h
 * @brief PFCP Session Manager for User Plane Function
 * @author OpenAirInterface
 * @date 2025
 *
 * This module implements session management functionality for the UPF control
 * plane, handling PFCP session establishment, modification, and deletion as
 * defined in 3GPP TS 29.244.
 *
 * Key 3GPP References:
 * - 3GPP TS 29.244: Interface between the Control Plane and the User Plane
 * nodes
 * - 3GPP TS 29.281: General Packet Radio System (GPRS) Tunnelling Protocol User
 *                    Plane (GTPv1-U)
 * - 3GPP TS 23.501: System architecture for the 5G System (5GS)
 * - 3GPP TS 29.244 Section 5.2: PFCP Session procedures
 * - 3GPP TS 29.244 Section 7.5: Information Elements (PDR, FAR, QER)
 */

#ifndef SESSION_MANAGER_H_
#define SESSION_MANAGER_H_

#include <cstdint>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

// Forward declarations
namespace pfcp {
class pfcp_session;
class pfcp_pdr;
class pfcp_far;
class pfcp_qer;
}  // namespace pfcp

class BpfMap;
class SessionProgramManager;
class UPF_XDPProgram;
struct itti_n4_session_establishment_request;
struct itti_n4_session_modification_request;
struct itti_n4_session_deletion_request;

/**
 * @enum TrafficDirection
 * @brief Traffic flow direction in 5G network
 *
 * Reference: 3GPP TS 29.244 Section 8.2.62 - Source Interface
 */
enum class TrafficDirection {
  Uplink,   ///< Traffic from UE to Data Network (Access → Core)
  Downlink  ///< Traffic from Data Network to UE (Core → Access)
};

/**
 * @struct SessionOperationResult
 * @brief Result structure for session operations
 *
 * Provides detailed feedback on session operations including success status,
 * error messages, and affected session identifier.
 */
struct SessionOperationResult {
  bool success;         ///< Operation success status
  std::string message;  ///< Result message or error description
  uint64_t
      seid;  ///< Session Endpoint Identifier (3GPP TS 29.244 Section 8.2.37)

  SessionOperationResult() : success(false), message(""), seid(0) {}

  SessionOperationResult(bool s, const std::string& msg, uint64_t id)
      : success(s), message(msg), seid(id) {}
};

/**
 * @class SessionManager
 * @brief Manages PFCP sessions and associated rules (PDR, FAR, QER)
 *
 * The SessionManager is the main control plane component responsible for:
 * - PFCP session lifecycle management (create, modify, delete)
 * - Packet Detection Rules (PDR) - 3GPP TS 29.244 Section 5.2.1
 * - Forwarding Action Rules (FAR) - 3GPP TS 29.244 Section 5.2.2
 * - QoS Enforcement Rules (QER) - 3GPP TS 29.244 Section 5.2.4
 *
 * Thread Safety: All public methods are thread-safe with internal locking.
 *
 * Reference Standards:
 * - 3GPP TS 29.244 Section 5: PFCP Session procedures
 * - 3GPP TS 29.244 Section 7.5: Information Elements
 *
 * @note This implementation follows Google C++ Style Guide
 */
class SessionManager {
 public:
  SessionManager();
  explicit SessionManager(
      std::shared_ptr<SessionProgramManager> session_program_manager);

  /**
   * @brief Destructor - cleans up all sessions
   */
  ~SessionManager();

  // Disable copy and move
  SessionManager(const SessionManager&) = delete;
  SessionManager& operator=(const SessionManager&) = delete;
  SessionManager(SessionManager&&)                 = delete;
  SessionManager& operator=(SessionManager&&) = delete;

  // ==========================================================================
  // Session Lifecycle Management
  // Reference: 3GPP TS 29.244 Section 5.2 - PFCP Session procedures
  // ==========================================================================

  /**
   * @brief Create a new PFCP session
   *
   * Implements session establishment as per 3GPP TS 29.244 Section 5.2.2.
   * Creates all associated PDRs, FARs, and QERs.
   *
   * @param session PFCP session object with configured rules
   * @return SessionOperationResult with success status
   *
   * @note Session must contain at least one PDR
   * @see 3GPP TS 29.244 Section 5.2.2 - PFCP Session Establishment
   */
  SessionOperationResult CreateSession(
      std::shared_ptr<pfcp::pfcp_session> session);

  /**
   * @brief Update existing PFCP session
   *
   * Modifies session parameters and associated rules as per 3GPP TS 29.244
   * Section 5.2.3.
   *
   * @param session Updated session object
   * @return SessionOperationResult with success status
   *
   * @see 3GPP TS 29.244 Section 5.2.3 - PFCP Session Modification
   */
  SessionOperationResult UpdateSession(
      std::shared_ptr<pfcp::pfcp_session> session);

  /**
   * @brief Delete PFCP session
   *
   * Removes session and all associated rules as per 3GPP TS 29.244
   * Section 5.2.4.
   *
   * @param seid Session Endpoint Identifier
   * @return SessionOperationResult with success status
   *
   * @see 3GPP TS 29.244 Section 5.2.4 - PFCP Session Deletion
   */
  SessionOperationResult DeleteSession(uint64_t seid);

  /**
   * @brief Query session by SEID
   * @param seid Session Endpoint Identifier
   * @return Shared pointer to session, or nullptr if not found
   */
  std::shared_ptr<pfcp::pfcp_session> GetSession(uint64_t seid) const;

  /**
   * @brief Get all active sessions
   * @return Vector of all active session pointers
   */
  std::vector<std::shared_ptr<pfcp::pfcp_session>> GetAllSessions() const;

  // ==========================================================================
  // N4 Message Handlers
  // Reference: 3GPP TS 29.244 Section 6 - Message Formats
  // ==========================================================================

  /**
   * @brief Handle PFCP Session Establishment Request
   *
   * Processes N4 session establishment message as per 3GPP TS 29.244
   * Section 7.5.2.2.
   *
   * @param session PFCP session object
   * @param est_req Establishment request (must not benull)
   * @param mod_req Modification request (can be null)
   * @param del_req Deletion request (can be null)
   * @return SessionOperationResult with success status
   *
   * @see 3GPP TS 29.244 Section 7.5.2.2 - PFCP Session Establishment Request
   */
  SessionOperationResult EstablishSession(
      std::shared_ptr<pfcp::pfcp_session> session,
      itti_n4_session_establishment_request* est_req = nullptr,
      itti_n4_session_modification_request* mod_req  = nullptr,
      itti_n4_session_deletion_request* del_req      = nullptr);

  /**
   * @brief Handle PFCP Session Modification Request
   *
   * Processes N4 session modification message as per 3GPP TS 29.244
   * Section 7.5.4.2. Supports:
   * - Creating new PDRs/FARs/QERs
   * - Updating existing rules
   * - Removing rules
   *
   * @param session Updated PFCP session object
   * @param est_req Establishment request (can be null)
   * @param mod_req Modification request (must not be null)
   * @param del_req Deletion request (can be null)
   * @return SessionOperationResult with success status
   *
   * @see 3GPP TS 29.244 Section 7.5.4.2 - PFCP Session Modification Request
   */
  SessionOperationResult ModifySession(
      std::shared_ptr<pfcp::pfcp_session> session,
      itti_n4_session_establishment_request* est_req = nullptr,
      itti_n4_session_modification_request* mod_req  = nullptr,
      itti_n4_session_deletion_request* del_req      = nullptr);

  /**
   * @brief Handle PFCP Session Deletion Request
   *
   * Processes N4 session deletion message as per 3GPP TS 29.244
   * Section 7.5.5.2.
   *
   * @param session PFCP session to remove
   * @param est_req Establishment request (can be null)
   * @param mod_req Modification request (can be null)
   * @param del_req Deletion request (must not be null)
   * @return SessionOperationResult with success status
   *
   * @see 3GPP TS 29.244 Section 7.5.5.2 - PFCP Session Deletion Request
   */
  SessionOperationResult RemoveSession(
      std::shared_ptr<pfcp::pfcp_session> session,
      itti_n4_session_establishment_request* est_req = nullptr,
      itti_n4_session_modification_request* mod_req  = nullptr,
      itti_n4_session_deletion_request* del_req      = nullptr);

  // ==========================================================================
  // PDR Management
  // Reference: 3GPP TS 29.244 Section 5.2.1 - Packet Detection Rule
  // ==========================================================================

  /**
   * @brief Add Packet Detection Rule to session
   *
   * Creates a new PDR as defined in 3GPP TS 29.244 Section 8.2.2.
   * PDR determines which packets belong to a session based on:
   * - Source Interface (3GPP TS 29.244 Section 8.2.62)
   * - F-TEID (3GPP TS 29.244 Section 8.2.3)
   * - UE IP Address (3GPP TS 29.244 Section 8.2.62)
   * - SDF Filter (3GPP TS 29.244 Section 8.2.5)
   *
   * @param seid Session Endpoint Identifier
   * @param pdr Packet Detection Rule to add
   * @return true if successful, false otherwise
   *
   * @see 3GPP TS 29.244 Section 8.2.2 - Create PDR IE
   */
  bool AddPdr(uint64_t seid, std::shared_ptr<pfcp::pfcp_pdr> pdr);

  /**
   * @brief Update existing Packet Detection Rule
   *
   * Modifies PDR parameters as per 3GPP TS 29.244 Section 8.2.9.
   *
   * @param seid Session Endpoint Identifier
   * @param pdr Updated Packet Detection Rule
   * @return true if successful, false otherwise
   *
   * @see 3GPP TS 29.244 Section 8.2.9 - Update PDR IE
   */
  bool UpdatePdr(uint64_t seid, std::shared_ptr<pfcp::pfcp_pdr> pdr);

  /**
   * @brief Remove Packet Detection Rule from session
   *
   * Deletes PDR as per 3GPP TS 29.244 Section 8.2.16.
   *
   * @param seid Session Endpoint Identifier
   * @param pdr_id PDR ID to remove
   * @return true if successful, false otherwise
   *
   * @see 3GPP TS 29.244 Section 8.2.16 - Remove PDR IE
   */
  bool RemovePdr(uint64_t seid, uint16_t pdr_id);

  // ==========================================================================
  // FAR Management
  // Reference: 3GPP TS 29.244 Section 5.2.2 - Forwarding Action Rule
  // ==========================================================================

  /**
   * @brief Add Forwarding Action Rule to session
   *
   * Creates a new FAR as defined in 3GPP TS 29.244 Section 8.2.3.
   * FAR specifies how to handle packets that match a PDR:
   * - Apply Action (forward, drop, buffer, notify)
   * - Forwarding Parameters (destination interface, outer header creation)
   *
   * @param seid Session Endpoint Identifier
   * @param far Forwarding Action Rule to add
   * @return true if successful, false otherwise
   *
   * @see 3GPP TS 29.244 Section 8.2.3 - Create FAR IE
   */
  bool AddFar(uint64_t seid, std::shared_ptr<pfcp::pfcp_far> far);

  /**
   * @brief Update existing Forwarding Action Rule
   *
   * Modifies FAR parameters as per 3GPP TS 29.244 Section 8.2.10.
   *
   * @param seid Session Endpoint Identifier
   * @param far Updated Forwarding Action Rule
   * @return true if successful, false otherwise
   *
   * @see 3GPP TS 29.244 Section 8.2.10 - Update FAR IE
   */
  bool UpdateFar(uint64_t seid, std::shared_ptr<pfcp::pfcp_far> far);

  /**
   * @brief Remove Forwarding Action Rule from session
   *
   * Deletes FAR as per 3GPP TS 29.244 Section 8.2.17.
   *
   * @param seid Session Endpoint Identifier
   * @param far_id FAR ID to remove
   * @return true if successful, false otherwise
   *
   * @see 3GPP TS 29.244 Section 8.2.17 - Remove FAR IE
   */
  bool RemoveFar(uint64_t seid, uint32_t far_id);

  // ==========================================================================
  // QER Management
  // Reference: 3GPP TS 29.244 Section 5.2.4 - QoS Enforcement Rule
  // ==========================================================================

  /**
   * @brief Add QoS Enforcement Rule to session
   *
   * Creates a new QER as defined in 3GPP TS 29.244 Section 8.2.4.
   * QER enforces QoS parameters:
   * - Maximum Bitrate (MBR) - 3GPP TS 29.244 Section 8.2.40
   * - Guaranteed Bitrate (GBR) - 3GPP TS 29.244 Section 8.2.41
   * - Gate Status - 3GPP TS 29.244 Section 8.2.25
   * - QFI - 3GPP TS 29.244 Section 8.2.89
   *
   * @param seid Session Endpoint Identifier
   * @param qer QoS Enforcement Rule to add
   * @return true if successful, false otherwise
   *
   * @see 3GPP TS 29.244 Section 8.2.4 - Create QER IE
   */
  bool AddQer(uint64_t seid, std::shared_ptr<pfcp::pfcp_qer> qer);

  /**
   * @brief Update existing QoS Enforcement Rule
   *
   * Modifies QER parameters as per 3GPP TS 29.244 Section 8.2.11.
   *
   * @param seid Session Endpoint Identifier
   * @param qer Updated QoS Enforcement Rule
   * @return true if successful, false otherwise
   *
   * @see 3GPP TS 29.244 Section 8.2.11 - Update QER IE
   */
  bool UpdateQer(uint64_t seid, std::shared_ptr<pfcp::pfcp_qer> qer);

  /**
   * @brief Remove QoS Enforcement Rule from session
   *
   * Deletes QER as per 3GPP TS 29.244 Section 8.2.18.
   *
   * @param seid Session Endpoint Identifier
   * @param qer_id QER ID to remove
   * @return true if successful, false otherwise
   *
   * @see 3GPP TS 29.244 Section 8.2.18 - Remove QER IE
   */
  bool RemoveQer(uint64_t seid, uint32_t qer_id);

  // ==========================================================================
  // Helper Methods
  // ==========================================================================

  /**
   * @brief Get FAR associated with a PDR
   *
   * Retrieves the FAR referenced by a PDR's FAR ID.
   *
   * @param session Session containing the PDR and FAR
   * @param pdr PDR to look up
   * @param out_far Output parameter for the found FAR
   * @return true if FAR was found, false otherwise
   */
  bool GetFarForPdr(
      std::shared_ptr<pfcp::pfcp_session> session,
      std::shared_ptr<pfcp::pfcp_pdr> pdr,
      std::shared_ptr<pfcp::pfcp_far>& out_far) const;

  /**
   * @brief Get QER associated with a PDR
   *
   * Retrieves the QER referenced by a PDR's QER ID.
   *
   * @param session Session containing the PDR and QER
   * @param pdr PDR to look up
   * @param out_qer Output parameter for the found QER
   * @return true if QER was found, false otherwise
   */
  bool GetQerForPdr(
      std::shared_ptr<pfcp::pfcp_session> session,
      std::shared_ptr<pfcp::pfcp_pdr> pdr,
      std::shared_ptr<pfcp::pfcp_qer>& out_qer) const;

  /**
   * @brief Find QER by ID in session
   * @param session Session to search
   * @param qer_id QER identifier
   * @return Pointer to QER if found, nullptr otherwise
   */
  std::shared_ptr<pfcp::pfcp_qer> FindQer(
      std::shared_ptr<pfcp::pfcp_session> session, uint32_t qer_id) const;

  /**
   * @brief Retrieve TEID from session (downlink direction)
   *
   * Extracts the Tunnel Endpoint Identifier from FAR outer header creation.
   * Reference: 3GPP TS 29.281 - GTPv1-U
   *
   * @param session Session to query
   * @return TEID value, or 0 if not found
   */
  uint32_t RetrieveTeid(std::shared_ptr<pfcp::pfcp_session> session) const;

  /**
   * @brief Find uplink TEID for a session
   * @param vector of Sessions Endpoint Identifier
   * @return Uplink TEID, or 0 if not found
   */
  uint64_t FindUplinkTeid(uint64_t seid) const;

 private:
  // ==========================================================================
  // Internal Methods
  // ==========================================================================

  /**
   * @brief Categorize PDRs into uplink and downlink based on source interface
   *
   * Separates PDRs by Source Interface IE (3GPP TS 29.244 Section 8.2.62):
   * - Access: Uplink PDRs
   * - Core: Downlink PDRs
   *
   * @param session Session containing PDRs to categorize
   */
  void CategorizePdrs(std::shared_ptr<pfcp::pfcp_session> session);

  /**
   * @brief Sort PDRs by precedence value
   *
   * Orders PDRs according to Precedence IE (3GPP TS 29.244 Section 8.2.29).
   * Lower precedence value = higher priority.
   *
   * @param pdrs Vector of PDRs to sort (sorted in-place)
   */
  void SortPdrs(std::vector<std::shared_ptr<pfcp::pfcp_pdr>>& pdrs);

  /**
   * @brief Compare two PDRs by precedence for sorting
   * @param first First PDR
   * @param second Second PDR
   * @return true if first has lower precedence (higher priority)
   */
  static bool ComparePdrPrecedence(
      const std::shared_ptr<pfcp::pfcp_pdr>& first,
      const std::shared_ptr<pfcp::pfcp_pdr>& second);

  /**
   * @brief Handle PDR removal from modification request
   * @param session Session to modify
   * @param mod_req Modification request containing PDRs to remove
   * @return Number of PDRs removed
   */
  size_t HandlePdrRemoval(
      std::shared_ptr<pfcp::pfcp_session> session,
      itti_n4_session_modification_request* mod_req);

  /**
   * @brief Handle FAR removal from modification request
   * @param session Session to modify
   * @param mod_req Modification request containing FARs to remove
   * @return Number of FARs removed
   */
  size_t HandleFarRemoval(
      std::shared_ptr<pfcp::pfcp_session> session,
      itti_n4_session_modification_request* mod_req);

  /**
   * @brief Handle QER removal from modification request
   * @param session Session to modify
   * @param mod_req Modification request containing QERs to remove
   * @return Number of QERs removed
   */
  size_t HandleQerRemoval(
      std::shared_ptr<pfcp::pfcp_session> session,
      itti_n4_session_modification_request* mod_req);

  /**
   * @brief Handle PDR updates from modification request
   * @param session Session to modify
   * @param mod_req Modification request containing PDRs to update
   * @return Number of PDRs updated
   */
  size_t HandlePdrUpdates(
      std::shared_ptr<pfcp::pfcp_session> session,
      itti_n4_session_modification_request* mod_req);

  /**
   * @brief Handle FAR updates from modification request
   * @param session Session to modify
   * @param mod_req Modification request containing FARs to update
   * @return Number of FARs updated
   */
  size_t HandleFarUpdates(
      std::shared_ptr<pfcp::pfcp_session> session,
      itti_n4_session_modification_request* mod_req);

  /**
   * @brief Handle QER updates from modification request
   * @param session Session to modify
   * @param mod_req Modification request containing QERs to update
   * @return Number of QERs updated
   */
  size_t HandleQerUpdates(
      std::shared_ptr<pfcp::pfcp_session> session,
      itti_n4_session_modification_request* mod_req);

  // ==========================================================================
  // Member Variables
  // ==========================================================================

  /// Session program manager for BPF program lifecycle
  std::shared_ptr<SessionProgramManager> session_program_manager_;

  /// XDP program interface
  // std::shared_ptr<UPF_XDPProgram> xdp_program_;

  /// Map of SEID to session objects
  std::unordered_map<uint64_t, std::shared_ptr<pfcp::pfcp_session>>
      seid_to_session_;

  /// List of all active sessions (for compatibility)
  std::vector<std::shared_ptr<pfcp::pfcp_session>> sessions_;

  /// Mutex for thread-safe access to session maps
  mutable std::mutex sessions_mutex_;
};

#endif  // SESSION_MANAGER_H_
