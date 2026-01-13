/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/**
 * @file SessionProgramManager.h
 * @brief BPF Program Manager for PFCP Sessions
 *
 * This module manages BPF/eBPF programs and maps for PFCP session processing
 * in the user plane data path. It handles the translation between PFCP IEs
 * and BPF data structures.
 *
 * Key 3GPP References:
 * - 3GPP TS 29.244: PFCP protocol specification
 * - 3GPP TS 29.281: GTPv1-U protocol for tunneling
 * - 3GPP TS 23.501: 5G System Architecture
 * - 3GPP TS 29.244 Section 8.2: Information Elements for PDR, FAR, QER
 * - 3GPP TS 29.244 Section 8.2.74: Outer Header Creation
 */

#ifndef SESSION_PROGRAM_MANAGER_H_
#define SESSION_PROGRAM_MANAGER_H_

#include <cstdint>
#include <array>
#include <map>
#include <memory>
#include <mutex>
#include <vector>
#include <set>

// Forward declarations
namespace pfcp {
class pfcp_session;
class pfcp_pdr;
class pfcp_far;
class pfcp_qer;
}  // namespace pfcp

class BpfMap;
class ISessionObserver;
class UPF_XDPProgram;
class QERProgram;
class SessionPrograms;
struct pfcp_pdr;
struct pfcp_far;
struct pfcp_qer;

/**
 * @struct PfcpProgramInfo
 * @brief Associates PFCP session with BPF program
 */
struct PfcpProgramInfo {
  uint64_t seid;                                ///< Session Endpoint ID
  std::shared_ptr<UPF_XDPProgram> xdp_program;  ///< Associated XDP program

  PfcpProgramInfo() : seid(0), xdp_program(nullptr) {}
};

/**
 * @class SessionProgramManager
 * @brief Manages BPF programs and maps for PFCP sessions
 *
 * This manager is responsible for:
 * - Converting PFCP IEs to BPF structures (3GPP TS 29.244 Section 8.2)
 * - Managing BPF maps for PDR/FAR/QER rules
 * - Updating ARP tables for next-hop resolution
 * - Synchronizing session state with data path
 *
 * Thread Safety: All public methods are thread-safe.
 *
 * @note Follows Google C++ Style Guide
 */
class SessionProgramManager {
 public:
  /**
   * @brief Destructor - cleans up all programs and sessions
   */
  virtual ~SessionProgramManager();

  /**
   * @brief Get singleton instance
   *
   * @return Reference to singleton instance
   *
   * @deprecated Use dependency injection in new code
   * @note Singleton pattern maintained for backward compatibility
   */
  static SessionProgramManager& GetInstance();

  // ==========================================================================
  // Session Lifecycle Management
  // ==========================================================================

  /**
   * @brief Create a new session program
   * @param seid Session Endpoint Identifier
   */
  void CreateSession(uint64_t seid);

  /**
   * @brief Remove session and its associated programs
   * @param seid Session Endpoint Identifier
   */
  void RemoveSession(uint64_t seid);

  /**
   * @brief Remove all sessions
   */
  void RemoveAllSessions();

  // ==========================================================================
  // BPF Map Management
  // ==========================================================================

  /**
   * @brief Set the TEID session map
   * @param map Shared pointer to BPF map
   */
  void SetTeidSessionMap(std::shared_ptr<BpfMap> map);

  /**
   * @brief Set the ARP table map
   * @param map Shared pointer to BPF map for ARP entries
   * @see RFC 826 - Address Resolution Protocol
   */
  void SetArpTableMap(std::shared_ptr<BpfMap> map);

  /**
   * @brief Store PDU session information in BPF map
   *
   * Updates the session mapping table with UE IP, TEIDs, and SEID.
   * This enables fast session lookup in the data path.
   *
   * @param xdp_program XDP program containing the maps
   * @param ue_ip UE IP address
   * @param teid_dl Downlink TEID (3GPP TS 29.281)
   * @param teid_ul Uplink TEID (3GPP TS 29.281)
   * @param seid Session Endpoint Identifier
   */
  void StorePduSessionInMap(
      std::shared_ptr<UPF_XDPProgram> xdp_program, uint32_t ue_ip,
      uint32_t teid_dl, uint32_t teid_ul, uint64_t seid);
  void storeETHPduSessionInMap(
      std::shared_ptr<UPF_XDPProgram> pUPF_XDPProgram, uint32_t teid_ul,
      uint32_t teid_dl, uint32_t n3IpAddress, uint64_t seid);

  // ==========================================================================
  // Pipeline Management
  // Reference: 3GPP TS 29.244 Section 5.2 - PFCP Session procedures
  // ==========================================================================

  /**
   * @brief Create complete BPF pipeline for a session
   *
   * Sets up all BPF maps and programs needed to process packets for this
   * session according to configured PDRs, FARs, and QERs.
   *
   * @param session PFCP session object
   */
  void CreatePipeline(std::shared_ptr<pfcp::pfcp_session> session);

  /**
   * @brief Modify existing BPF pipeline
   *
   * Updates BPF maps to reflect changes in session configuration.
   * TEIDs default to 0 (unchanged) if not provided.
   *
   * @param session Updated session object
   * @param teid_ul Uplink TEID (default: 0 = unchanged)
   * @param teid_dl Downlink TEID (default: 0 = unchanged)
   */
  void ModifyPipeline(
      std::shared_ptr<pfcp::pfcp_session> session, uint32_t teid_ul = 0,
      uint32_t teid_dl = 0);

  /**
   * @brief Remove BPF pipeline for a session
   * @param seid Session Endpoint Identifier
   */
  void RemovePipeline(uint64_t seid);

  // ==========================================================================
  // PFCP IE to BPF Conversion
  // Reference: 3GPP TS 29.244 Section 8.2 - Information Elements
  // ==========================================================================

  /**
   * @brief Convert PFCP FAR to BPF FAR structure
   *
   * Translates Forwarding Action Rule IE (3GPP TS 29.244 Section 8.2.3)
   * into BPF-compatible structure for data path processing.
   *
   * Key fields converted:
   * - Apply Action (3GPP TS 29.244 Section 8.2.23)
   * - Forwarding Parameters (3GPP TS 29.244 Section 8.2.74)
   * - Outer Header Creation (3GPP TS 29.244 Section 8.2.74)
   *
   * @param far PFCP FAR object
   * @return BPF FAR structure
   *
   * @see 3GPP TS 29.244 Section 8.2.3 - Create FAR IE
   */
  struct pfcp_far ConvertFar(std::shared_ptr<pfcp::pfcp_far> far) const;

  /**
   * @brief Convert PFCP PDR to BPF PDR structure
   *
   * Translates Packet Detection Rule IE (3GPP TS 29.244 Section 8.2.2)
   * into BPF-compatible structure for packet classification.
   *
   * Key fields converted:
   * - PDI (Packet Detection Information)
   * - Precedence (3GPP TS 29.244 Section 8.2.29)
   * - FAR ID reference
   * - QER ID reference
   *
   * @param pdr PFCP PDR object
   * @return BPF PDR structure
   *
   * @see 3GPP TS 29.244 Section 8.2.2 - Create PDR IE
   */
  struct pfcp_pdr ConvertPdr(std::shared_ptr<pfcp::pfcp_pdr> pdr) const;

  /**
   * @brief Convert PFCP QER to BPF QER structure
   *
   * Translates QoS Enforcement Rule IE (3GPP TS 29.244 Section 8.2.4)
   * into BPF-compatible structure for QoS enforcement.
   *
   * Key fields converted:
   * - Gate Status (3GPP TS 29.244 Section 8.2.25)
   * - MBR (Maximum Bitrate) (3GPP TS 29.244 Section 8.2.40)
   * - GBR (Guaranteed Bitrate) (3GPP TS 29.244 Section 8.2.41)
   * - QFI (QoS Flow Identifier) (3GPP TS 29.244 Section 8.2.89)
   *
   * @param qer PFCP QER object
   * @return BPF QER structure
   *
   * @see 3GPP TS 29.244 Section 8.2.4 - Create QER IE
   */
  struct pfcp_qer ConvertQer(std::shared_ptr<pfcp::pfcp_qer> qer) const;

  // ==========================================================================
  // ARP Table Management
  // Reference: RFC 826 - Address Resolution Protocol
  // ==========================================================================

  //   /**
  //    * @brief Update ARP table for N6 interface (Data Network side)
  //    *
  //    * Resolves MAC address for next-hop toward data network and updates
  //    * ARP table in BPF maps for fast packet forwarding.
  //    *
  //    * @param upf_xdp_program Shared pointer to UPF XDP program
  //    * @param dn_ip Data network IP address
  //    * @param upf_n6_ip UPF N6 interface IP
  //    *
  //    * @see 3GPP TS 23.501 Section 5.8.2.3 - N6 Interface
  //    */
  //   void UpdateArpTableForN6(
  //       std::shared_ptr<UPF_XDPProgram> upf_xdp_program, uint32_t dn_ip,
  //       uint32_t upf_n6_ip);

  //   /**
  //    * @brief Update ARP table for N3 interface (RAN side)
  //    *
  //    * Resolves MAC address for next-hop toward gNodeB and updates
  //    * ARP table in BPF maps for fast packet forwarding.
  //    *
  //    * @param upf_xdp_program Shared pointer to UPF XDP program
  //    * @param gnb_ip gNodeB IP address
  //    * @param upf_n3_ip UPF N3 interface IP
  //    * @param seid Session Endpoint Identifier
  //    *
  //    * @see 3GPP TS 23.501 Section 5.8.2.2 - N3 Interface
  //    */
  //   void UpdateArpTableForN3(
  //       std::shared_ptr<UPF_XDPProgram> upf_xdp_program, uint32_t gnb_ip,
  //       uint32_t upf_n3_ip, uint64_t seid);

  /****************************************** */
  /**
   * @brief Update ARP table for N6 interface (Data Network side)
   *
   * Resolves MAC address for next-hop toward data network and updates
   * ARP table in BPF maps for fast packet forwarding.
   *
   * @param upf_xdp_program Shared pointer to UPF XDP program
   * @param dn_ip Data network IP address
   * @param upf_n6_ip UPF N6 interface IP
   *
   * @see 3GPP TS 23.501 Section 5.8.2.3 - N6 Interface
   * @return MAC address as string (e.g., "aa:bb:cc:dd:ee:ff")
   */
  std::string UpdateArpTableForN6(
      std::shared_ptr<UPF_XDPProgram> upf_xdp_program, uint32_t dn_ip,
      uint32_t upf_n6_ip);

  /**
   * @brief Update ARP table for N3 interface (RAN side)
   *
   * Resolves MAC address for next-hop toward gNodeB and updates
   * ARP table in BPF maps for fast packet forwarding.
   *
   * @param upf_xdp_program Shared pointer to UPF XDP program
   * @param gnb_ip gNodeB IP address
   * @param upf_n3_ip UPF N3 interface IP
   * @param seid Session Endpoint Identifier
   *
   * @see 3GPP TS 23.501 Section 5.8.2.2 - N3 Interface
   * @return MAC address as string (e.g., "aa:bb:cc:dd:ee:ff")
   */
  std::string UpdateArpTableForN3(
      std::shared_ptr<UPF_XDPProgram> upf_xdp_program, uint32_t gnb_ip,
      uint32_t upf_n3_ip, uint64_t seid);
  /********************************************* */

  /**
   * @brief Get next-hop IP address
   *
   * Determines the next-hop IP for routing packets. If destination is on
   * same subnet, returns destination IP; otherwise returns gateway IP.
   *
   * @param local_ip Local IP address
   * @param remote_ip Remote IP address
   * @return Next-hop IP address
   */
  uint32_t GetNextHopIp(uint32_t local_ip, uint32_t remote_ip) const;

  // ==========================================================================
  // Session Query and Management
  // ==========================================================================

  /**
   * @brief Add PFCP program to session tracking
   * @param seid Session Endpoint Identifier
   * @param xdp_program XDP program pointer
   */
  void AddPfcpProgram(
      uint64_t seid, std::shared_ptr<UPF_XDPProgram> xdp_program);

  /**
   * @brief Find session programs by SEID
   * @param seid Session Endpoint Identifier
   * @return Pointer to SessionPrograms if found, nullptr otherwise
   */
  std::shared_ptr<SessionPrograms> FindSessionPrograms(uint64_t seid) const;

  /**
   * @brief Get gNodeB IP from FAR outer header creation
   *
   * Extracts gNodeB IP address from FAR's Outer Header Creation IE
   * (3GPP TS 29.244 Section 8.2.74).
   *
   * @param far FAR containing outer header creation info
   * @return gNodeB IP address
   */
  uint32_t GetGnodebIp(std::shared_ptr<pfcp::pfcp_far> far) const;

  /**
   * @brief Retrieve gNodeB IP from session
   * @param session Session to query
   * @return gNodeB IP address
   */
  uint32_t RetrieveGnbIp(std::shared_ptr<pfcp::pfcp_session> session) const;

  /**
   * @brief Retrieve UE IP from session
   * @param session Session to query
   * @return UE IP address
   */
  uint32_t RetrieveUeIp(std::shared_ptr<pfcp::pfcp_session> session) const;

  /**
   * @brief Get FAR associated with PDR
   * @param session Session containing rules
   * @param pdr PDR to look up
   * @param out_far Output FAR pointer
   * @return true if found
   */
  bool GetFarForPdr(
      std::shared_ptr<pfcp::pfcp_session> session,
      std::shared_ptr<pfcp::pfcp_pdr> pdr,
      std::shared_ptr<pfcp::pfcp_far>& out_far) const;

  /**
   * @brief Get QER associated with PDR
   * @param session Session containing rules
   * @param pdr PDR to look up
   * @param out_qer Output QER pointer
   * @return true if found
   */
  bool GetQerForPdr(
      std::shared_ptr<pfcp::pfcp_session> session,
      std::shared_ptr<pfcp::pfcp_pdr> pdr,
      std::shared_ptr<pfcp::pfcp_qer>& out_qer) const;

  // ==========================================================================
  // Observer Pattern Support
  // ==========================================================================

  /**
   * @brief Set observer for session program state changes
   * @param observer Observer to notify of changes (usually UserPlaneComponent)
   *
   * When SessionProgramManager creates/updates/removes session programs,
   * it notifies the observer so XDP program maps can be updated.
   */
  void SetSessionObserver(ISessionObserver* observer);

  // ==========================================================================
  // Public Data (for compatibility)
  // ==========================================================================

  /// Vector of PFCP program information
  std::shared_ptr<std::vector<PfcpProgramInfo>> pfcp_programs;

 private:
  // ==========================================================================
  // Internal Methods
  // ==========================================================================

  /**
   * @brief Constructor
   * @param max_sessions Maximum number of concurrent sessions
   */
  explicit SessionProgramManager(size_t max_sessions = 1024);

  /**
   * @brief Get an empty slot in the program array
   * @return Index of empty slot, or -1 if none available
   */
  int32_t GetEmptySlot();

  // ==========================================================================
  // Member Variables
  // ==========================================================================

  /// TEID to session mapping (BPF map)
  std::shared_ptr<BpfMap> teid_session_map_;

  /// ARP table mapping (BPF map)
  std::shared_ptr<BpfMap> arp_table_map_;

  /// Observer for session program state changes (usually UserPlaneComponent)
  ISessionObserver* session_observer_;

  /// Map of SEID to SessionPrograms
  std::map<uint64_t, std::shared_ptr<SessionPrograms>> session_programs_map_;

  /// Map of SEID to QER programs for QoS enforcement
  std::map<uint64_t, std::shared_ptr<QERProgram>> qer_programs_map_;

  /// Array tracking program slots
  std::array<int64_t, 1024> program_array_;

  /// Maximum number of sessions
  size_t max_sessions_;

  /// Mutex for thread-safe access
  mutable std::mutex mutex_;

  /// ARP update tracking (per session)
  std::map<uint64_t, std::set<uint32_t>> session_n6_arp_cache_;
  std::map<uint64_t, std::set<uint32_t>> session_n3_arp_cache_;
};

#endif  // SESSION_PROGRAM_MANAGER_H_
