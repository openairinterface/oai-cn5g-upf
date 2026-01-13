/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/**
 * @file upf_xdp_user.h
 * @brief XDP program management for UPF packet processing
 *
 * This class manages XDP (eXpress Data Path) programs for fast-path packet
 * processing in the User Plane Function. XDP provides kernel-bypass packet
 * processing with hardware offload capabilities.
 *
 * Key Features:
 * - Dual XDP programs: Uplink (GTP-U/N3) and Downlink (UDP/N6)
 * - Session-based packet forwarding with BPF maps
 * - ARP resolution for next-hop forwarding
 * - PDR (Packet Detection Rules) matching
 * - SDF (Service Data Flow) filtering
 * - QoS enablement per session
 * - Framed routing support for advanced routing scenarios
 *
 * Architecture:
 * - Uplink: GTP-U packets from N3 interface → decapsulation → routing
 * - Downlink: IP packets from N6 interface → encapsulation → forwarding
 *
 * XDP Hook Points:
 * - N3 (GTP) interface: xdp_uplink section
 * - N6 (UDP) interface: xdp_downlink or xdp_qos section
 *
 * BPF Maps Managed:
 * - session_by_ue_ip_map: UE IP → Session ID mapping
 * - arp_table_map: ARP resolution table
 * - redirect_interfaces_map: Interface redirection
 * - upf_interface_map: UPF reference points (N3, N4, N6)
 * - pdrs_per_session_map: PDRs for each session
 * - rules_match_pdr_map: Rule matching state
 * - sdf_filters_map: SDF filter definitions
 * - session_qos_enabled_map: QoS enablement per session
 * - framed_route_mapping: Framed routing mappings
 *
 * XDP Performance:
 * - Native/Driver mode: Best performance, hardware offload
 * - SKB mode: Fallback, compatibility
 * - Typical throughput: 10-40 Gbps depending on hardware
 *
 * Reference Standards:
 * - Linux XDP: https://www.kernel.org/doc/html/latest/networking/af_xdp.html
 * - 3GPP TS 29.281: GTP-U protocol
 * - 3GPP TS 29.244: PFCP protocol for session management
 * - 3GPP TS 23.501: 5G System Architecture (N3, N6 interfaces)
 *
 * @note This implementation follows Google C++ Style Guide
 */

#ifndef UPF_XDP_USER_H_
#define UPF_XDP_USER_H_

#include <ProgramLifeCycle.hpp>
#include <linux/bpf.h>
#include <memory>
#include <string>
#include <upf_xdp_kern_skel.h>
#include <wrappers/BPFMap.hpp>
#include "interfaces.h"
#include <framed_routing_bpf.h>
#include "upf_config.hpp"
#include "BPFProgram.h"

using namespace oai::config;
extern upf_config upf_cfg;

// Forward declarations
class BPFMaps;
class BPFMap;

/**
 * @brief Type alias for XDP program lifecycle management
 *
 * Manages the complete lifecycle of the XDP kernel program:
 * open → load → attach → link → teardown
 */
using UPF_XDPProgramLifeCycle = ProgramLifeCycle<upf_xdp_kern_c>;

/**
 * @class UPF_XDPProgram
 * @brief Manages XDP programs for User Plane Function packet processing
 *
 * This class provides high-performance packet processing using XDP (eXpress
 * Data Path), a Linux kernel feature for fast packet processing at the driver
 * level.
 *
 * Key Responsibilities:
 * - Initialize and configure XDP programs for uplink/downlink
 * - Manage BPF maps for session state and routing
 * - Configure interface-specific packet processing
 * - Handle ARP resolution for packet forwarding
 * - Support framed routing for advanced scenarios
 * - Provide QoS enforcement hooks
 *
 * Lifecycle:
 * 1. Construction: Initialize with interfaces
 * 2. Setup: Load and attach XDP programs
 * 3. Runtime: Maps managed by SessionManager
 * 4. Teardown: Detach programs and cleanup
 *
 * Thread Safety: Not thread-safe. Use from single thread (typically main).
 *
 * XDP Modes:
 * - XDP_FLAGS_DRV_MODE: Driver mode (best performance, hardware offload)
 * - XDP_FLAGS_SKB_MODE: SKB mode (fallback, compatibility)
 *
 * @note This implementation follows Google C++ Style Guide
 * @note Inherits from BPFProgram base class
 */
class UPF_XDPProgram : public BPFProgram {
 public:
  /**
   * @brief Constructor - initializes XDP program for specified interfaces
   *
   * Creates the XDP program manager for the given network interfaces.
   * Configures BPF maps based on system capabilities and UPF configuration.
   *
   * @param gtp_interface GTP-U interface name (N3, e.g., "n3", "eth0")
   * @param udp_interface UDP interface name (N6, e.g., "n6", "eth1")
   * @param upf_cfg UPF configuration with map sizes and limits
   *
   * @throws std::runtime_error if skeleton creation fails
   * @throws std::runtime_error if map configuration fails
   *
   * Configuration Validation:
   * - Checks interface count against system limits
   * - Validates redirect interface count
   * - Ensures PDR limits don't exceed compile-time constants
   *
   * Usage:
   * @code
   * upf_config cfg = load_config();
   * auto xdp_program = std::make_shared<UPF_XDPProgram>("n3", "n6", cfg);
   * xdp_program->Setup(true);  // Enable QoS
   * @endcode
   */
  explicit UPF_XDPProgram(
      const std::string& gtp_interface, const std::string& udp_interface,
      const upf_config& upf_cfg);

  /**
   * @brief Destructor - cleans up XDP program resources
   *
   * Detaches XDP programs from interfaces and frees BPF resources.
   * Maps are automatically cleaned up by the kernel.
   */
  virtual ~UPF_XDPProgram();

  /**
   * @brief Setup and attach XDP programs to interfaces
   *
   * Performs the complete XDP program initialization:
   * 1. Opens BPF skeleton
   * 2. Initializes all BPF maps
   * 3. Loads programs into kernel
   * 4. Attaches to kernel hooks
   * 5. Links XDP programs to network interfaces
   * 6. Configures reference points (N3, N4, N6)
   * 7. Sets up egress interface mappings
   *
   * @param is_qos_enabled If true, attach QoS enforcement (xdp_qos section)
   *                       If false, attach standard downlink (xdp_downlink)
   *
   * @throws std::runtime_error if interface not found
   * @throws std::runtime_error if XDP attach fails
   *
   * XDP Sections:
   * - xdp_uplink: Attached to GTP interface (N3)
   * - xdp_downlink: Attached to UDP interface (N6) when QoS disabled
   * - xdp_qos: Attached to UDP interface (N6) when QoS enabled
   *
   * Usage:
   * @code
   * xdp_program->Setup(upf_cfg.enable_qos);
   * @endcode
   */
  void Setup(bool is_qos_enabled);

  /**
   * @brief Get all BPF maps from the program
   *
   * Returns the BPFMaps container which provides access to all maps
   * in the XDP program by name.
   *
   * @return std::shared_ptr<BPFMaps> Container of all BPF maps
   */
  std::shared_ptr<BPFMaps> GetMaps();

  /**
   * @brief Teardown XDP programs and cleanup resources
   *
   * Detaches XDP programs from interfaces, unloads from kernel,
   * and frees all resources. Maps are cleaned up by kernel.
   *
   * @note Safe to call multiple times
   */
  void TearDown();

  /**
   * @brief Create entry in UPF interface map for a reference point
   *
   * Stores interface configuration (IP, port, name) for UPF reference
   * points in the BPF map for kernel access.
   *
   * @param reference_point Type of reference point (N3, N4, N6, N9, N19)
   *
   * Reference Points (3GPP TS 23.501):
   * - N3: Interface between RAN and UPF (GTP-U)
   * - N4: Interface between SMF and UPF (PFCP)
   * - N6: Interface between UPF and Data Network
   * - N9: Interface between UPFs (for uplink classifier)
   * - N19: Interface between SMF and UPF (policy control)
   */
  void CreateUpfInterfaceMapEntry(reference_point_t reference_point);

  /**
   * @brief Remove a program from the program map
   *
   * Removes the BPF program file descriptor for a given key.
   * Used during session deletion.
   *
   * @param key Program map key (typically session ID)
   */
  void RemoveProgramMap(uint32_t key);

  /**
   * @brief Get BPF map by name for dynamic access (CRITICAL METHOD)
   *
   * Provides access to BPF maps by their string name. This method is
   * used by SessionProgramManager for dynamic map access.
   *
   * Supported Map Names (with aliases):
   * - "session_map", "session_by_ue_ip_map" → Session mapping
   * - "arp_table", "arp_table_map" → ARP resolution
   * - "redirect_interfaces_map" → Interface redirection
   * - "upf_interface_map" → UPF reference points
   * - "pdrs_per_session_map" → PDRs per session
   * - "rules_match_pdr_map" → Rule matching
   * - "sdf_filters_map" → SDF filters
   * - "session_qos_enabled_map" → QoS enablement
   * - "m_framed_route_mapping" → Framed routing
   *
   * @param map_name Name of the map (supports aliases)
   * @return std::shared_ptr<BPFMap> Pointer to map, or nullptr if not found
   *
   * @note Prefer using specific getter methods for better performance
   * @note This method enables SessionProgramManager to work generically
   *
   * Usage:
   * @code
   * // In SessionProgramManager:
   * auto session_map = xdp_program->GetMapByName("session_map");
   * if (session_map) {
   *   session_map->Update(ue_ip, session_id, BPF_ANY);
   * }
   * @endcode
   */
  std::shared_ptr<BPFMap> GetMapByName(const std::string& map_name);

  // Framed Routing Methods
  std::shared_ptr<BPFMap> GetFramedRouteMappingMap();
  void UpdateFramedRouteMappingMap(uint32_t ue_ip, FramedRoutingKeyBPF key);
  void RemoveFramedRoute(FramedRoutingKeyBPF key);
  void SetFramedRouting(bool enable);

  // Map Getters - Direct access for performance
  std::shared_ptr<BPFMap> GetEgressInterfaceMap() const;
  std::shared_ptr<BPFMap> GetArpTableMap() const;
  std::shared_ptr<BPFMap> GetIfaceMap() const;
  std::shared_ptr<BPFMap> GetSessionMappingMap() const;
  std::shared_ptr<BPFMap> GetRulesMatchPdrMap() const;
  std::shared_ptr<BPFMap> GetSessionPdrsMap() const;
  std::shared_ptr<BPFMap> GetSdfFilterMap() const;
  std::shared_ptr<BPFMap> GetQosEnablingMap() const;

  // XDP Mode and Statistics Methods
  size_t GetMapCount() const;
  bool IsNativeXdp(const std::string& interface) const;
  std::string GetXdpModeString(const std::string& interface) const;

 private:
  /**
   * @brief Initialize all BPF map wrappers
   *
   * Creates BPFMap wrappers for all maps in the skeleton.
   * Called during Setup() after skeleton is opened.
   */
  void InitializeMaps();

  /**
   * @brief Configure PFCP session lookup maps
   *
   * Sets max_entries for all maps based on configuration.
   * Must be called after open, before load.
   *
   * @param skel Pointer to opened BPF skeleton
   * @param upf_cfg UPF configuration with map sizes
   *
   * @throws std::runtime_error if configuration fails
   */
  void ConfigurePfcpSessionLookupMaps(
      struct upf_xdp_kern_c* skel, const upf_config& upf_cfg);

  // Skeleton and lifecycle
  upf_xdp_kern_c* skeleton_;  ///< BPF skeleton (libbpf)
  std::shared_ptr<UPF_XDPProgramLifeCycle> lifecycle_;  ///< Lifecycle manager

  // Interface configuration
  std::string gtp_interface_;  ///< GTP-U interface name (N3)
  std::string udp_interface_;  ///< UDP interface name (N6)

  // Map containers
  std::shared_ptr<BPFMaps> maps_;  ///< All BPF maps container

  // Individual map pointers (for fast access)
  std::shared_ptr<BPFMap> teid_session_map_;      ///< TEID to session mapping
  std::shared_ptr<BPFMap> session_mapping_map_;   ///< UE IP to session
  std::shared_ptr<BPFMap> egress_interface_map_;  ///< Egress interface IDs
  std::shared_ptr<BPFMap> arp_table_map_;         ///< ARP resolution table
  std::shared_ptr<BPFMap> upf_iface_map_;         ///< UPF interface config
  std::shared_ptr<BPFMap> rules_match_pdr_map_;   ///< Rule matching state
  std::shared_ptr<BPFMap> session_pdrs_map_;      ///< PDRs per session
  std::shared_ptr<BPFMap> sdf_filter_map_;        ///< SDF filter definitions
  std::shared_ptr<BPFMap> qos_enabling_map_;      ///< QoS per session
  std::shared_ptr<BPFMap> framed_route_mapping_map_;  ///< Framed route mapping
  std::shared_ptr<BPFMap> framed_route_flag_map_;  ///< Framed route enable flag
};

#endif  // UPF_XDP_USER_H_
