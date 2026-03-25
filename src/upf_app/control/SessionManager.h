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
 * - 3GPP TS 29.244 V17.10.0: Interface between the Control Plane and the User
 *                              Plane nodes
 * - 3GPP TS 29.281 V17.3.0: General Packet Radio System (GPRS) Tunnelling
 *                             Protocol User Plane (GTPv1-U)
 * - 3GPP TS 23.501: System architecture for the 5G System (5GS)
 * - §5.2  PFCP Session procedures (overview)
 * - §7.5  N4 Session procedure message IEs
 * - §8.2  Information Element definitions
 *
 * @par Changelog
 * | Date       | Author | Description                                        |
 * |------------|--------|----------------------------------------------------|
 * | 2025-xx-xx | OAI    | Initial implementation                             |
 * | 2026-03-11 | OAI    | Harmonised §-refs to TS 29.244 V17.10.0; fixed     |
 * |            |        | Source Interface §-ref in TrafficDirection; removed |
 * |            |        | vacuous Google Style Guide note; fixed "Baffering"  |
 * |            |        | typo; corrected MBR/GBR/Gate Status/URR ID §-refs. |
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
class pfcp_urr;
class pfcp_bar;
class pfcp_mar;
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
 * Reference: 3GPP TS 29.244 §8.2.2 - Source Interface
 *            (§8.2.62 is UE IP Address — distinct IE)
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
 * - Packet Detection Rules (PDR)     — §7.5.2.2 / §8.2.2 Source Interface
 * - Forwarding Action Rules (FAR)    — §7.5.2.3 / §8.2.74 FAR ID
 * - QoS Enforcement Rules (QER)      — §7.5.2.4 / §8.2.75 QER ID
 *
 * Thread Safety: All public methods are thread-safe with internal locking.
 *
 * Reference Standards:
 * - 3GPP TS 29.244 V17.10.0 §5.2  PFCP Session procedures (overview)
 * - 3GPP TS 29.244 V17.10.0 §7.5  N4 Session procedure message IEs
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
  // Reference: 3GPP TS 29.244 §5.2 - PFCP Session procedures (overview)
  // ==========================================================================

  /**
   * @brief Create a new PFCP session
   *
   * Implements session establishment as per 3GPP TS 29.244 §7.5.2.
   * Creates all associated PDRs, FARs, and QERs.
   *
   * @param session PFCP session object with configured rules
   * @return SessionOperationResult with success status
   *
   * @note Session must contain at least one PDR
   * @see 3GPP TS 29.244 §7.5.2 - PFCP Session Establishment Request
   */
  SessionOperationResult CreateSession(
      std::shared_ptr<pfcp::pfcp_session> session);

  /**
   * @brief Update existing PFCP session
   *
   * Modifies session parameters and associated rules as per 3GPP TS 29.244
   * §7.5.4.
   *
   * @param session Updated session object
   * @return SessionOperationResult with success status
   *
   * @see 3GPP TS 29.244 §7.5.4 - PFCP Session Modification Request
   */
  SessionOperationResult UpdateSession(
      std::shared_ptr<pfcp::pfcp_session> session);

  /**
   * @brief Delete PFCP session
   *
   * Removes session and all associated rules as per 3GPP TS 29.244 §7.5.6.
   *
   * @param seid Session Endpoint Identifier
   * @return SessionOperationResult with success status
   *
   * @see 3GPP TS 29.244 §7.5.6 - PFCP Session Deletion Request
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
  // Reference: 3GPP TS 29.244 §7 - N4 Message Formats
  // ==========================================================================

  /**
   * @brief Handle PFCP Session Establishment Request
   *
   * Processes N4 session establishment message as per 3GPP TS 29.244 §7.5.2.
   *
   * @param session PFCP session object
   * @param est_req Establishment request (must not be null)
   * @param mod_req Modification request (can be null)
   * @param del_req Deletion request (can be null)
   * @return SessionOperationResult with success status
   *
   * @see 3GPP TS 29.244 §7.5.2 - PFCP Session Establishment Request
   *      Table 7.5.2.2-1 — Create PDR IE
   */
  SessionOperationResult EstablishSession(
      std::shared_ptr<pfcp::pfcp_session> session,
      itti_n4_session_establishment_request* est_req = nullptr,
      itti_n4_session_modification_request* mod_req  = nullptr,
      itti_n4_session_deletion_request* del_req      = nullptr);

  /**
   * @brief Handle PFCP Session Modification Request
   *
   * Processes N4 session modification message as per 3GPP TS 29.244 §7.5.4.
   * Supports:
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
   * @see 3GPP TS 29.244 §7.5.4 - PFCP Session Modification Request
   */
  SessionOperationResult ModifySession(
      std::shared_ptr<pfcp::pfcp_session> session,
      itti_n4_session_establishment_request* est_req = nullptr,
      itti_n4_session_modification_request* mod_req  = nullptr,
      itti_n4_session_deletion_request* del_req      = nullptr);

  /**
   * @brief Handle PFCP Session Deletion Request
   *
   * Processes N4 session deletion message as per 3GPP TS 29.244 §7.5.6.
   *
   * @param session PFCP session to remove
   * @param est_req Establishment request (can be null)
   * @param mod_req Modification request (can be null)
   * @param del_req Deletion request (must not be null)
   * @return SessionOperationResult with success status
   *
   * @see 3GPP TS 29.244 §7.5.6 - PFCP Session Deletion Request
   */
  SessionOperationResult RemoveSession(
      std::shared_ptr<pfcp::pfcp_session> session,
      itti_n4_session_establishment_request* est_req = nullptr,
      itti_n4_session_modification_request* mod_req  = nullptr,
      itti_n4_session_deletion_request* del_req      = nullptr);

  // ==========================================================================
  // PDR Management
  // Reference: 3GPP TS 29.244 §5.2.1 — Packet Detection Rule
  // ==========================================================================

  /**
   * @brief Add Packet Detection Rule to session
   *
   * Creates a new PDR as per Table 7.5.2.2-1 (Create PDR grouped IE).
   * PDR determines which packets belong to a session based on:
   * - Source Interface (§8.2.2)
   * - F-TEID         (§8.2.3)
   * - UE IP Address  (§8.2.62)
   * - SDF Filter     (§8.2.5)
   *
   * @param seid Session Endpoint Identifier
   * @param pdr Packet Detection Rule to add
   * @return true if successful, false otherwise
   *
   * @see Table 7.5.2.2-1 — Create PDR IE
   */
  bool AddPdr(uint64_t seid, std::shared_ptr<pfcp::pfcp_pdr> pdr);

  /**
   * @brief Update existing Packet Detection Rule
   *
   * Modifies PDR parameters as per Table 7.5.4.3-1 (Update PDR grouped IE).
   *
   * @param seid Session Endpoint Identifier
   * @param pdr Updated Packet Detection Rule
   * @return true if successful, false otherwise
   *
   * @see Table 7.5.4.3-1 — Update PDR IE
   */
  bool UpdatePdr(uint64_t seid, std::shared_ptr<pfcp::pfcp_pdr> pdr);

  /**
   * @brief Remove Packet Detection Rule from session
   *
   * Deletes PDR as per Table 7.5.4.2-1 (Remove PDR grouped IE).
   *
   * @param seid Session Endpoint Identifier
   * @param pdr_id PDR ID to remove
   * @return true if successful, false otherwise
   *
   * @see Table 7.5.4.2-1 — Remove PDR IE
   *      §8.2.36 — PDR ID
   */
  bool RemovePdr(uint64_t seid, uint16_t pdr_id);

  // ==========================================================================
  // FAR Management
  // Reference: 3GPP TS 29.244 §5.2.2 — Forwarding Action Rule
  // ==========================================================================

  /**
   * @brief Add Forwarding Action Rule to session
   *
   * Creates a new FAR as per Table 7.5.2.3-1 (Create FAR grouped IE).
   * FAR specifies how to handle packets that match a PDR:
   * - Apply Action (forward, drop, buffer, notify) — §8.2.26
   * - FAR ID                                       — §8.2.74
   * - Forwarding Parameters (dest interface, OHC)
   *
   * @param seid Session Endpoint Identifier
   * @param far Forwarding Action Rule to add
   * @return true if successful, false otherwise
   *
   * @see Table 7.5.2.3-1 — Create FAR IE
   */
  bool AddFar(uint64_t seid, std::shared_ptr<pfcp::pfcp_far> far);

  /**
   * @brief Update existing Forwarding Action Rule
   *
   * Modifies FAR parameters as per Table 7.5.4.4-1 (Update FAR grouped IE).
   *
   * @param seid Session Endpoint Identifier
   * @param far Updated Forwarding Action Rule
   * @return true if successful, false otherwise
   *
   * @see Table 7.5.4.4-1 — Update FAR IE
   */
  bool UpdateFar(uint64_t seid, std::shared_ptr<pfcp::pfcp_far> far);

  /**
   * @brief Remove Forwarding Action Rule from session
   *
   * Deletes FAR as per Table 7.5.4.2-1 (Remove FAR grouped IE).
   *
   * @param seid Session Endpoint Identifier
   * @param far_id FAR ID to remove
   * @return true if successful, false otherwise
   *
   * @see Table 7.5.4.2-1 — Remove FAR IE
   *      §8.2.74 — FAR ID
   */
  bool RemoveFar(uint64_t seid, uint32_t far_id);

  // ==========================================================================
  // QER Management
  // Reference: 3GPP TS 29.244 §5.2.4 — QoS Enforcement Rule
  // ==========================================================================

  /**
   * @brief Add QoS Enforcement Rule to session
   *
   * Creates a new QER as per Table 7.5.2.4-1 (Create QER grouped IE).
   * QER enforces QoS parameters:
   * - Maximum Bitrate (MBR)  — §8.2.8
   * - Guaranteed Bitrate (GBR) — §8.2.9
   * - Gate Status            — §8.2.7
   * - QFI                    — §8.2.89
   * - QER ID                 — §8.2.75
   *
   * @param seid Session Endpoint Identifier
   * @param qer QoS Enforcement Rule to add
   * @return true if successful, false otherwise
   *
   * @see Table 7.5.2.4-1 — Create QER IE
   */
  bool AddQer(uint64_t seid, std::shared_ptr<pfcp::pfcp_qer> qer);

  /**
   * @brief Update existing QoS Enforcement Rule
   *
   * Modifies QER parameters as per Table 7.5.4.5-1 (Update QER grouped IE).
   *
   * @param seid Session Endpoint Identifier
   * @param qer Updated QoS Enforcement Rule
   * @return true if successful, false otherwise
   *
   * @see Table 7.5.4.5-1 — Update QER IE
   */
  bool UpdateQer(uint64_t seid, std::shared_ptr<pfcp::pfcp_qer> qer);

  /**
   * @brief Remove QoS Enforcement Rule from session
   *
   * Deletes QER as per Table 7.5.4.2-1 (Remove QER grouped IE).
   *
   * @param seid Session Endpoint Identifier
   * @param qer_id QER ID to remove
   * @return true if successful, false otherwise
   *
   * @see Table 7.5.4.2-1 — Remove QER IE
   *      §8.2.75 — QER ID
   */
  bool RemoveQer(uint64_t seid, uint32_t qer_id);

  // ==========================================================================
  // URR Management
  // Reference: 3GPP TS 29.244 §8.2.54 — URR ID
  //            Table 7.5.2.x-1 — Create URR IE
  //            Table 7.5.4.x-1 — Update/Remove URR IE
  // ==========================================================================

  /**
   * @brief Add Usage Reporting Rule to session
   *
   * Creates a new URR for volume/time measurement and periodic reporting.
   * URR is referenced from PDR via urr_id IE (§8.2.54 — URR ID).
   *
   * @param seid Session Endpoint Identifier
   * @param urr Usage Reporting Rule to add
   * @return true if successful, false otherwise
   *
   * @see Table 7.5.2.x-1 — Create URR IE
   */
  bool AddUrr(uint64_t seid, std::shared_ptr<pfcp::pfcp_urr> urr);

  /**
   * @brief Update existing Usage Reporting Rule
   *
   * Modifies URR parameters (triggers, thresholds, quotas) while preserving
   * active volume counters in urr_volume_counters_map (BPF_NOEXIST semantics).
   *
   * @param seid Session Endpoint Identifier
   * @param urr Updated Usage Reporting Rule
   * @return true if successful, false otherwise
   *
   * @see 3GPP TS 29.244 Section 8.2.12 - Update URR IE
   */
  bool UpdateUrr(uint64_t seid, std::shared_ptr<pfcp::pfcp_urr> urr);

  /**
   * @brief Remove Usage Reporting Rule from session
   *
   * @param seid Session Endpoint Identifier
   * @param urr_id URR ID to remove
   * @return true if successful, false otherwise
   *
   * @see 3GPP TS 29.244 Section 8.2.19 - Remove URR IE
   */
  bool RemoveUrr(uint64_t seid, uint32_t urr_id);

  // ==========================================================================
  // BAR Management
  // Reference: 3GPP TS 29.244 §8.2.57 — BAR ID
  //            Table 7.5.2.x-1 — Create BAR IE
  //            Table 7.5.4.x-1 — Update/Remove BAR IE
  // ==========================================================================

  /**
   * @brief Add Buffering Action Rule to session
   *
   * Creates a new BAR for DL buffering and DDN notification suppression.
   * BAR is referenced from FAR (not PDR) via bar_id when buff bit is set.
   *
   * @param seid Session Endpoint Identifier
   * @param bar Buffering Action Rule to add
   * @return true if successful, false otherwise
   *
   * @see 3GPP TS 29.244 Section 8.2.6 - Create BAR IE
   */
  bool AddBar(uint64_t seid, std::shared_ptr<pfcp::pfcp_bar> bar);

  /**
   * @brief Update existing Buffering Action Rule
   *
   * Modifies BAR parameters (DDN delay, packet count) while preserving
   * active bar_state_map entries (BPF_NOEXIST semantics).
   *
   * @param seid Session Endpoint Identifier
   * @param bar Updated Buffering Action Rule
   * @return true if successful, false otherwise
   *
   * @see 3GPP TS 29.244 Section 8.2.13 - Update BAR IE
   */
  bool UpdateBar(uint64_t seid, std::shared_ptr<pfcp::pfcp_bar> bar);

  /**
   * @brief Remove Buffering Action Rule from session
   *
   * @param seid Session Endpoint Identifier
   * @param bar_id BAR ID to remove
   * @return true if successful, false otherwise
   *
   * @see 3GPP TS 29.244 Section 8.2.20 - Remove BAR IE
   */
  bool RemoveBar(uint64_t seid, uint32_t bar_id);

  // ==========================================================================
  // MAR Management
  // Reference: 3GPP TS 29.244 §8.2.123 — MAR ID
  //            §7.5.2.8 — Create MAR IE
  //            §7.5.4.16 — Update MAR IE
  //            §7.5.4.15 — Remove MAR IE
  //            3GPP TS 23.501 §5.32 — ATSSS
  // ==========================================================================

  /**
   * @brief Add Multi-Access Rule to session
   *
   * Creates a new MAR for ATSSS traffic steering, switching, and splitting.
   * MAR is referenced from PDR via mar_id IE for multi-access sessions.
   *
   * @param seid Session Endpoint Identifier
   * @param mar Multi-Access Rule to add
   * @return true if successful, false otherwise
   *
   * @see 3GPP TS 29.244 Section 8.2.7 - Create MAR IE
   * @see 3GPP TS 23.501 Section 5.32 - ATSSS
   */
  bool AddMar(uint64_t seid, std::shared_ptr<pfcp::pfcp_mar> mar);

  /**
   * @brief Update existing Multi-Access Rule
   *
   * Modifies MAR parameters (steering mode, AFAI 3GPP, AFAI Non-3GPP).
   *
   * @param seid Session Endpoint Identifier
   * @param mar Updated Multi-Access Rule
   * @return true if successful, false otherwise
   *
   * @see 3GPP TS 29.244 Section 8.2.14 - Update MAR IE
   */
  bool UpdateMar(uint64_t seid, std::shared_ptr<pfcp::pfcp_mar> mar);

  /**
   * @brief Remove Multi-Access Rule from session
   *
   * @param seid Session Endpoint Identifier
   * @param mar_id MAR ID to remove
   * @return true if successful, false otherwise
   *
   * @see 3GPP TS 29.244 Section 8.2.21 - Remove MAR IE
   */
  bool RemoveMar(uint64_t seid, uint32_t mar_id);

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
  //   uint32_t RetrieveDownlinkTeid(
  //       std::shared_ptr<pfcp::pfcp_session> session) const;

  //   /**
  //    * @brief Find uplink TEID for a session
  //    * @param seid  session id to query
  //    * @return Uplink TEID, or 0 if not found
  //    */
  //   uint32_t FindUplinkTeid(uint64_t seid) const;

  //   /**
  //    * @brief Retrieve uplink TEID for a session
  //    * @param session Session to query
  //    * @return Uplink TEID, or 0 if not found
  //    */
  //   uint32_t RetrieveUplinkTeid(
  //       std::shared_ptr<pfcp::pfcp_session> session) const;

  // Extract uplink TEID from a specific PDR
  static uint32_t GetUplinkTeidFromPdr(std::shared_ptr<pfcp::pfcp_pdr> pdr);

  // Extract downlink TEID from a specific FAR
  static uint32_t GetDownlinkTeidFromFar(std::shared_ptr<pfcp::pfcp_far> far);

 private:
  // ==========================================================================
  // Internal Methods
  // ==========================================================================

  /**
   * @brief Get session without acquiring mutex (caller must hold
   * sessions_mutex_)
   *
   * Used internally by CRUD methods that already hold the lock to avoid
   * recursive mutex deadlock.
   *
   * @param seid Session Endpoint Identifier
   * @return Shared pointer to session, or nullptr if not found
   */
  std::shared_ptr<pfcp::pfcp_session> GetSessionUnlocked(uint64_t seid) const;

  /**
   * @brief Categorize PDRs into uplink and downlink based on source interface
   *
   * Separates PDRs by Source Interface IE (§8.2.2 — Source Interface):
   * - Access: Uplink PDRs
   * - Core:   Downlink PDRs
   *
   * @param session Session containing PDRs to categorize
   */
  void CategorizePdrs(std::shared_ptr<pfcp::pfcp_session> session);

  /**
   * @brief Sort PDRs by precedence value
   *
   * Orders PDRs according to Precedence IE (§8.2.11 — Precedence).
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

  /**
   * @brief Handle URR removal from modification request
   * @see 3GPP TS 29.244 Section 8.2.19 - Remove URR IE
   */
  size_t HandleUrrRemoval(
      std::shared_ptr<pfcp::pfcp_session> session,
      itti_n4_session_modification_request* mod_req);

  /**
   * @brief Handle BAR removal from modification request
   * @see 3GPP TS 29.244 Section 8.2.20 - Remove BAR IE
   */
  size_t HandleBarRemoval(
      std::shared_ptr<pfcp::pfcp_session> session,
      itti_n4_session_modification_request* mod_req);

  /**
   * @brief Handle MAR removal from modification request
   * @see 3GPP TS 29.244 Section 8.2.21 - Remove MAR IE
   */
  size_t HandleMarRemoval(
      std::shared_ptr<pfcp::pfcp_session> session,
      itti_n4_session_modification_request* mod_req);

  /**
   * @brief Handle URR updates from modification request
   *
   * Applies Update URR IE fields (reporting triggers, volume threshold/quota,
   * time threshold, measurement period, monitoring time) to existing URRs.
   * Volume counters in urr_volume_counters_map are preserved (not reset).
   *
   * @see 3GPP TS 29.244 Section 8.2.12 - Update URR IE
   */
  size_t HandleUrrUpdates(
      std::shared_ptr<pfcp::pfcp_session> session,
      itti_n4_session_modification_request* mod_req);

  /**
   * @brief Handle BAR updates from modification request
   *
   * Applies Update BAR IE fields (DL notification delay, suggested buffering
   * packet count) to existing BARs. Bar state (DDN tracking) is preserved.
   *
   * @see 3GPP TS 29.244 Section 8.2.13 - Update BAR IE
   */
  size_t HandleBarUpdates(
      std::shared_ptr<pfcp::pfcp_session> session,
      itti_n4_session_modification_request* mod_req);

  /**
   * @brief Handle MAR updates from modification request
   *
   * Applies Update MAR IE fields (steering mode, AFAI 3GPP, AFAI Non-3GPP)
   * to existing MARs. Updates mar_rules_map in BPF.
   *
   * @see 3GPP TS 29.244 Section 8.2.14 - Update MAR IE
   */
  size_t HandleMarUpdates(
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
