/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include "config.hpp"
#include "upf_config.hpp"
#include "common_defs.h"
#include "UpfInfo.h"

constexpr auto UPF_CONFIG_INSTANCE_ID            = "instance_id";
constexpr auto UPF_CONFIG_SUPPORT_FEATURES       = "support_features";
constexpr auto UPF_CONFIG_UPF_INFO               = "upf_info";
constexpr auto UPF_CONFIG_DATAPATH_CONFIGURATION = "datapath_configuration";

constexpr auto UPF_CONFIG_INSTANCE_ID_LABEL      = "Instance ID";
constexpr auto UPF_CONFIG_SUPPORT_FEATURES_LABEL = "Support Features";
constexpr auto UPF_CONFIG_UPF_INFO_LABEL         = "UPF INFO";
constexpr auto UPF_CONFIG_DATAPATH_CONFIGURATION_LABEL =
    "Datapath Configuration";

//------------------------------------------------------
//           Support Features
//------------------------------------------------------
constexpr auto UPF_ENABLE_BPF     = "enable_bpf_datapath";
constexpr auto UPF_ENABLE_QOS     = "enable_qos";
constexpr auto UPF_ENABLE_URR     = "enable_urr";
constexpr auto UPF_ENABLE_BAR     = "enable_bar";
constexpr auto UPF_ENABLE_MAR     = "enable_mar";
constexpr auto UPF_ENABLE_SNAT    = "enable_snat";
constexpr auto UPF_ENABLE_FR      = "enable_fr";
constexpr auto UPF_ENABLE_ETH_PDU = "enable_eth_pdu";

constexpr auto UPF_ENABLE_BPF_LABEL     = "Enable BPF Datapath";
constexpr auto UPF_ENABLE_QOS_LABEL     = "Enable QoS Enforcement (QER)";
constexpr auto UPF_ENABLE_URR_LABEL     = "Enable Usage Reporting (URR)";
constexpr auto UPF_ENABLE_BAR_LABEL     = "Enable Buffering (BAR)";
constexpr auto UPF_ENABLE_MAR_LABEL     = "Enable Multi Access (MAR)";
constexpr auto UPF_ENABLE_SNAT_LABEL    = "Enable SNAT";
constexpr auto UPF_ENABLE_FR_LABEL      = "Enable Framed Routing";
constexpr auto UPF_ENABLE_ETH_PDU_LABEL = "Enable Ethernet PDU Sessions";

//------------------------------------------------------
//           N6 Gateway
//------------------------------------------------------
constexpr auto UPF_CONFIG_REMOTE_N6_GW       = "remote_n6_gw";
constexpr auto UPF_CONFIG_REMOTE_N6_GW_LABEL = "Remote N6 Gateway";

//------------------------------------------------------
//           UPF Reference Points
//------------------------------------------------------
constexpr auto UPF_CONFIG_N3_LABEL = "n3";
constexpr auto UPF_CONFIG_N6_LABEL = "n6";
constexpr auto UPF_CONFIG_N4_LABEL = "n4";

//------------------------------------------------------
//           Datapath Configuration
//------------------------------------------------------
constexpr auto UPF_MAX_PDU_SESSIONS         = "max_pdu_sessions";
constexpr auto UPF_MAX_PDRS_PER_PDU_SESSION = "max_pdrs_per_pdu_session";
constexpr auto UPF_MAX_FARS_PER_PDU_SESSION = "max_fars_per_pdu_session";
constexpr auto UPF_MAX_QERS_PER_PDU_SESSION = "max_qers_per_pdu_session";
constexpr auto UPF_MAX_URRS_PER_PDU_SESSION = "max_urrs_per_pdu_session";
constexpr auto UPF_MAX_BARS_PER_PDU_SESSION = "max_bars_per_pdu_session";
constexpr auto UPF_MAX_SDF_FILTERS_PER_PDU_SESSION =
    "max_sdf_filters_per_pdu_session";
constexpr auto UPF_MAX_SDF_FILTER_STRING_LENGTH =
    "max_sdf_filter_string_length";
constexpr auto UPF_MAX_UPF_INTERFACES          = "max_upf_interfaces";
constexpr auto UPF_MAX_UPF_REDIRECT_INTERFACES = "max_upf_redirect_interfaces";
constexpr auto UPF_MAX_ARP_ENTRIES             = "max_arp_entries";
constexpr auto UPF_MAX_APPLICATION_IDS_PER_SESSION =
    "max_application_ids_per_session";
constexpr auto UPF_MAX_TRAFFIC_ENDPOINTS_PER_SESSION =
    "max_traffic_endpoints_per_session";
constexpr auto UPF_MAX_ETHERNET_PACKET_FILTERS_PER_SESSION =
    "max_ethernet_packet_filters_per_session";
constexpr auto UPF_MAX_REDUNDANT_TRANSMISSION_PARAMS_PER_SESSION =
    "max_redundant_transmission_params_per_session";

constexpr auto UPF_MAX_PDU_SESSIONS_LABEL = "Max PDU Sessions";
constexpr auto UPF_MAX_PDRS_PER_PDU_SESSION_LABEL =
    "Max PDR Rules per PDU Session";
constexpr auto UPF_MAX_FARS_PER_PDU_SESSION_LABEL =
    "Max FAR Rules per PDU Session";
constexpr auto UPF_MAX_QERS_PER_PDU_SESSION_LABEL =
    "Max QER Rules per PDU Session";
constexpr auto UPF_MAX_URRS_PER_PDU_SESSION_LABEL =
    "Max URR Rules per PDU Session";
constexpr auto UPF_MAX_BARS_PER_PDU_SESSION_LABEL =
    "Max BAR Rules per PDU Session";
constexpr auto UPF_MAX_SDF_FILTERS_PER_PDU_SESSION_LABEL =
    "Max SDF Filters per PDU Session";
constexpr auto UPF_MAX_SDF_FILTER_STRING_LENGTH_LABEL =
    "MAX Size Buffer for SDF Filter Description String";
constexpr auto UPF_MAX_UPF_INTERFACES_LABEL = "Max UPF Interfaces";
constexpr auto UPF_MAX_UPF_REDIRECT_INTERFACES_LABEL =
    "Max UPF Redirect Interfaces";
constexpr auto UPF_MAX_ARP_ENTRIES_LABEL = "Max ARP Entries";
constexpr auto UPF_MAX_APPLICATION_IDS_PER_SESSION_LABEL =
    "Max Application IDs per PDU Session";
constexpr auto UPF_MAX_TRAFFIC_ENDPOINTS_PER_SESSION_LABEL =
    "Max Traffic Endpoints per PDU Session";
constexpr auto UPF_MAX_ETHERNET_PACKET_FILTERS_PER_SESSION_LABEL =
    "Max Ethernet Packet Filters per PDU Session";
constexpr auto UPF_MAX_REDUNDANT_TRANSMISSION_PARAMS_PER_SESSION_LABEL =
    "Max Redundant Transmission Params per PDU Session";

//------------------------------------------------------
//     Datapath Configuration Default Values
//     Based on basic_nrf_config_ebpf.yaml (lines 373-564)
//------------------------------------------------------
// PFCP Session Limits
constexpr int UPF_DEFAULT_MAX_PDU_SESSIONS         = 100;
constexpr int UPF_DEFAULT_MAX_PDRS_PER_PDU_SESSION = 8;
constexpr int UPF_DEFAULT_MAX_FARS_PER_PDU_SESSION = 8;
constexpr int UPF_DEFAULT_MAX_QERS_PER_PDU_SESSION = 8;
constexpr int UPF_DEFAULT_MAX_URRS_PER_PDU_SESSION = 4;
constexpr int UPF_DEFAULT_MAX_BARS_PER_PDU_SESSION = 2;

// SDF Filter Configuration
constexpr int UPF_DEFAULT_MAX_SDF_FILTERS_PER_PDU_SESSION = 8;
constexpr int UPF_DEFAULT_MAX_SDF_FILTER_STRING_LENGTH    = 512;

// Network Interface Limits
constexpr int UPF_DEFAULT_MAX_UPF_INTERFACES          = 4;
constexpr int UPF_DEFAULT_MAX_UPF_REDIRECT_INTERFACES = 2;
constexpr int UPF_DEFAULT_MAX_ARP_ENTRIES             = 256;

// Advanced Features (3GPP Rel-16+)
constexpr int UPF_DEFAULT_MAX_APPLICATION_IDS_PER_SESSION               = 8;
constexpr int UPF_DEFAULT_MAX_TRAFFIC_ENDPOINTS_PER_SESSION             = 2;
constexpr int UPF_DEFAULT_MAX_ETHERNET_PACKET_FILTERS_PER_SESSION       = 4;
constexpr int UPF_DEFAULT_MAX_REDUNDANT_TRANSMISSION_PARAMS_PER_SESSION = 0;

//------------------------------------------------------
//           SMF List
//------------------------------------------------------
constexpr auto UPF_CONFIG_SMF_LIST = "smfs";

//-----------------------------------------------------------------------------------------------
//-----------------------------------------------------------------------------------------------
/**
 * @brief UPF Support Features Configuration
 *
 * Manages feature flags that enable or disable optional UPF capabilities.
 * These flags control which 3GPP features are active in the UPF implementation.
 *
 * Features include:
 * - eBPF datapath (vs traditional userspace datapath)
 * - QoS enforcement (QER rules)
 * - Usage reporting (URR rules)
 * - Buffering (BAR rules)
 * - Multi-access routing (MAR)
 * - Source NAT
 * - Framed routing
 * - Ethernet PDU sessions
 *
 * All features default to disabled (false) for safety and can be enabled
 * via YAML configuration or programmatically.
 *
 * @note Feature flags are read during UPF initialization and cannot be
 *       changed at runtime without restarting the UPF.
 *
 * @see 3GPP TS 29.244 for PFCP feature definitions
 *
 * @section example Example Usage
 * @code
 * // Enable BPF datapath and QoS
 * upf_support_features features(true, true, false, false, false, false, false,
 * false);
 *
 * // Or load from YAML
 * upf_support_features features(false, false, false, false, false, false,
 * false, false); features.from_yaml(yaml_node["support_features"]);
 *
 * // Check if feature is enabled
 * if (features.get_option_enable_bpf_datapath()) {
 *   // Initialize BPF datapath
 * }
 * @endcode
 *
 * @author OpenAirInterface
 * @version 1.0
 */
namespace oai::config {
class upf_support_features : public config_type {
 private:
  /**
   * @brief Enable eBPF-based datapath
   *
   * When enabled, the UPF uses eBPF programs for high-performance packet
   * processing instead of the traditional userspace datapath.
   *
   * Default: false (use userspace datapath)
   *
   * @note eBPF datapath requires:
   *       - Linux kernel 5.4+
   *       - BPF maps properly configured
   *       - Appropriate kernel capabilities (CAP_BPF, CAP_NET_ADMIN)
   */
  option_config_value m_enable_bpf_datapath{};

  /**
   * @brief Enable QoS enforcement (QER rules)
   *
   * When enabled, the UPF processes QoS Enforcement Rules (QER) to apply
   * MBR (Maximum Bit Rate), GBR (Guaranteed Bit Rate), and QoS markings.
   *
   * Default: false
   *
   * @see 3GPP TS 29.244 Section 7.5.2.4 (QER IE)
   */
  option_config_value m_enable_qos{};

  /**
   * @brief Enable usage reporting (URR rules)
   *
   * When enabled, the UPF collects and reports usage statistics (volume,
   * duration, etc.) according to Usage Reporting Rules (URR).
   *
   * Default: false
   *
   * @note Requires connection to charging/policy functions
   * @see 3GPP TS 29.244 Section 7.5.2.5 (URR IE)
   */
  option_config_value m_enable_urr{};

  /**
   * @brief Enable buffering (BAR rules)
   *
   * When enabled, the UPF buffers downlink packets during idle mode according
   * to Buffering Action Rules (BAR) and triggers downlink data notification.
   *
   * Default: false
   *
   * @note Required for idle mode DRX (Discontinuous Reception)
   * @see 3GPP TS 29.244 Section 7.5.2.6 (BAR IE)
   */
  option_config_value m_enable_bar{};

  /**
   * @brief Enable multi-access routing (MAR)
   *
   * When enabled, the UPF supports Multi-Access PDU connectivity where
   * a single PDU session can be accessed via multiple access networks.
   *
   * Default: false
   *
   * @note 3GPP Rel-16+ feature for ATSSS (Access Traffic Steering/Switching)
   * @see 3GPP TS 23.501 Section 5.32 (ATSSS)
   */
  option_config_value m_enable_mar{};

  /**
   * @brief Enable Source NAT (SNAT)
   *
   * When enabled, the UPF performs Source Network Address Translation
   * on N6 interface for internet-bound traffic.
   *
   * Default: false
   *
   * @note Required when UE IP addresses are private and need translation
   *       for internet access
   */
  option_config_value m_enable_snat{};

  /**
   * @brief Enable framed routing
   *
   * When enabled, the UPF supports framed routing mode where traffic
   * is routed based on frame/tunnel information rather than IP routing.
   *
   * Default: false
   *
   * @note Used in specific enterprise/campus network scenarios
   */
  option_config_value m_enable_fr{};
  option_config_value m_enable_eth_pdu{};
  option_config_value m_ignore_qfi_for_uplink{};

 public:
  /**
   * @brief Construct with explicit feature flags
   *
   * Initializes all 8 feature flags with provided boolean values.
   * This is the primary constructor used when features are known at
   * compile/initialization time.
   *
   * @param enable_bpf_datapath Enable eBPF datapath (default: false)
   * @param enable_qos Enable QoS enforcement (default: false)
   * @param enable_urr Enable usage reporting (default: false)
   * @param enable_bar Enable buffering (default: false)
   * @param enable_mar Enable multi-access routing (default: false)
   * @param enable_snat Enable Source NAT (default: false)
   * @param enable_fr Enable framed routing (default: false)
   * @param enable_eth_pdu Enable Ethernet PDU sessions (default: false)
   *
   * @note All features default to disabled for safety. Enable only
   *       features that are needed and properly configured.
   *
   * @section example Example
   * @code
   * // Enable only BPF datapath and QoS
   * upf_support_features features(
   *     true,  // BPF
   *     true,  // QoS
   *     false, // URR
   *     false, // BAR
   *     false, // MAR
   *     false, // SNAT
   *     false, // FR
   *     false  // ETH_PDU
   * );
   * @endcode
   */
  explicit upf_support_features(
      bool enable_bpf_datapath, bool enable_qos, bool enable_urr,
      bool enable_bar, bool enable_mar, bool enable_snat, bool enable_fr,
      bool enable_eth_pdu);

  /**
   * @brief Parse feature flags from YAML configuration
   *
   * Reads feature enable flags from the YAML node. Missing flags retain
   * their current values (typically false from constructor).
   *
   * @param node YAML node containing support_features section
   *
   * @throws YAML::Exception If YAML parsing fails
   *
   * @note YAML keys match constant names: enable_bpf_datapath, enable_qos, etc.
   *
   * @section yaml_example YAML Example
   * @code{.yaml}
   * support_features:
   *   enable_bpf_datapath: yes
   *   enable_qos: yes
   *   enable_urr: no
   *   enable_bar: no
   *   enable_mar: no
   *   enable_snat: yes
   *   enable_fr: no
   *   enable_eth_pdu: no
   * @endcode
   */
  void from_yaml(const YAML::Node& node) override;

  /**
   * @brief Convert feature configuration to string representation
   *
   * Generates a human-readable string showing the state of all feature flags.
   *
   * @param indent Indentation prefix for formatting
   * @return Formatted string with all feature states
   *
   * @note Output format: "Feature Name: enabled/disabled"
   */
  [[nodiscard]] std::string to_string(const std::string& indent) const override;

  /**
   * @brief Check if BPF datapath is enabled
   * @return true if eBPF datapath is enabled, false otherwise
   */
  [[nodiscard]] bool get_option_enable_bpf_datapath() const;

  /**
   * @brief Check if QoS enforcement is enabled
   * @return true if QER rules are processed, false otherwise
   */
  [[nodiscard]] bool get_option_enable_qos() const;

  /**
   * @brief Check if usage reporting is enabled
   * @return true if URR rules are processed, false otherwise
   */
  [[nodiscard]] bool get_option_enable_urr() const;

  /**
   * @brief Check if buffering is enabled
   * @return true if BAR rules are processed, false otherwise
   */
  [[nodiscard]] bool get_option_enable_bar() const;

  /**
   * @brief Check if multi-access routing is enabled
   * @return true if MAR is supported, false otherwise
   */
  [[nodiscard]] bool get_option_enable_mar() const;

  /**
   * @brief Check if Source NAT is enabled
   * @return true if SNAT is performed on N6, false otherwise
   */
  [[nodiscard]] bool get_option_enable_snat() const;

  /**
   * @brief Check if framed routing is enabled
   * @return true if framed routing is used, false otherwise
   */
  [[nodiscard]] bool get_option_enable_fr() const;

  /**
   * @brief Check if Ethernet PDU sessions are enabled
   * @return true if Ethernet PDU session type is supported, false otherwise
   */
  [[nodiscard]] bool get_option_enable_eth_pdu() const;
};

//-----------------------------------------------------------------------------------------------
/**
 * @brief UPF Datapath BPF Map Configuration Manager
 *
 * Manages all BPF map capacity parameters for the UPF data plane based on
 * 3GPP TS 29.244 (PFCP specification). This class encapsulates the
 * configuration of BPF map sizes used by the eBPF datapath implementation.
 *
 * The class provides:
 * - Parsing from YAML configuration files
 * - Comprehensive validation (range checks, cross-parameter validation)
 * - Overflow prevention for derived BPF map sizes
 * - JSON serialization/deserialization
 * - Default values based on basic_nrf_config_ebpf.yaml
 *
 * All parameters follow 3GPP TS 29.244 specifications and are validated
 * before use to prevent BPF map creation failures.
 *
 * @note This class is part of the UPF YAML configuration framework and should
 *       not be used directly outside of upf_config_yaml.
 *
 * @see upf_config For the runtime configuration structure
 * @see 3GPP TS 29.244 For PFCP specification details
 *
 * @section references 3GPP References
 * - Section 7.2.2: CP F-SEID (PFCP sessions)
 * - Section 7.5.2.2: PDR (Packet Detection Rule)
 * - Section 7.5.2.3: FAR (Forwarding Action Rule)
 * - Section 7.5.2.4: QER (QoS Enforcement Rule)
 * - Section 7.5.2.5: URR (Usage Reporting Rule)
 * - Section 7.5.2.6: BAR (Buffering Action Rule)
 * - Table 7.5.2.2-2: SDF Filters
 *
 * @section example Example Usage
 * @code
 * upf_datapath_configuration config("datapath_configuration");
 * config.from_yaml(yaml_node["datapath_configuration"]);
 * config.validate();  // Must be called before use!
 * int max_sessions = config.get_max_pdu_sessions();
 * @endcode
 *
 * @author OpenAirInterface
 * @version 1.0
 * @since Rel-16
 */

class upf_datapath_configuration : public config_type {
 private:
  /**
   * @brief Maximum number of concurrent PFCP sessions
   *
   * Controls the size of the main session lookup BPF map. This is the
   * fundamental limit on how many UE PDU sessions can be active simultaneously.
   *
   * Default: 100 sessions
   * Valid range: [1, 100000]
   *
   * @note This directly controls the size of 'session_by_ue_ip_map' BPF map
   * @see 3GPP TS 29.244 Section 7.2.2 (CP F-SEID)
   */
  int_config_value m_max_pdu_sessions{};

  /**
   * @brief Maximum PDRs per PDU session
   *
   * Packet Detection Rules define traffic matching criteria for each session.
   * Typical deployments use 2-4 PDRs (uplink/downlink × default/dedicated).
   *
   * Default: 8 PDRs
   * Valid range: [1, 64]
   *
   * @note Total BPF map size = max_pdu_sessions × max_pdrs_per_pdu_session
   * @see 3GPP TS 29.244 Section 7.5.2.2 (PDR IE)
   */
  int_config_value m_max_pdrs_per_pdu_session{};

  /**
   * @brief Maximum FARs per PDU session
   *
   * Forwarding Action Rules define how packets matching PDRs should be
   * forwarded (forward, duplicate, drop, buffer).
   *
   * Default: 8 FARs
   * Valid range: [1, 64]
   *
   * @note Typically 1 FAR per PDR in simple configurations
   * @see 3GPP TS 29.244 Section 7.5.2.3 (FAR IE)
   */
  int_config_value m_max_fars_per_pdu_session{};

  /**
   * @brief Maximum QERs per PDU session
   *
   * QoS Enforcement Rules define QoS parameters (MBR, GBR, QFI) for traffic.
   * Used for QoS differentiation within a PDU session.
   *
   * Default: 8 QERs
   * Valid range: [1, 32]
   *
   * @note Only relevant if UPF_ENABLE_QOS feature is enabled
   * @see 3GPP TS 29.244 Section 7.5.2.4 (QER IE)
   */
  int_config_value m_max_qers_per_pdu_session{};

  /**
   * @brief Maximum URRs per PDU session
   *
   * Usage Reporting Rules define when and what usage information should be
   * reported to the SMF (volume, duration, etc.).
   *
   * Default: 4 URRs
   * Valid range: [0, 16]
   *
   * @note Only relevant if UPF_ENABLE_URR feature is enabled
   * @see 3GPP TS 29.244 Section 7.5.2.5 (URR IE)
   */
  int_config_value m_max_urrs_per_pdu_session{};

  /**
   * @brief Maximum BARs per PDU session
   *
   * Buffering Action Rules define how packets should be buffered during
   * downlink data notification procedures.
   *
   * Default: 2 BARs
   * Valid range: [0, 8]
   *
   * @note Only relevant if UPF_ENABLE_BAR feature is enabled
   * @see 3GPP TS 29.244 Section 7.5.2.6 (BAR IE)
   */
  int_config_value m_max_bars_per_pdu_session{};

  /**
   * @brief Maximum SDF filters per PDU session
   *
   * Service Data Flow filters provide fine-grained traffic classification
   * based on 5-tuple, application ID, etc.
   *
   * Default: 8 filters
   * Valid range: [1, 32]
   *
   * @note Each filter has associated string length defined separately
   * @see 3GPP TS 29.244 Table 7.5.2.2-2 (SDF Filter)
   */
  int_config_value m_max_sdf_filters_per_pdu_session{};

  /**
   * @brief Maximum length of SDF filter description string
   *
   * Controls buffer size for SDF filter flow descriptions (e.g., IPFilterRule).
   *
   * Default: 512 bytes
   * Valid range: [64, 2048]
   *
   * @note Larger values allow more complex filter expressions
   * @see 3GPP TS 29.244 Section 8.2.5 (SDF Filter IE)
   */
  int_config_value m_max_sdf_filter_string_length{};

  /**
   * @brief Maximum number of UPF network interfaces
   *
   * Total number of network interfaces the UPF can manage.
   * Typically includes: N3 (RAN), N6 (DN), N4 (SMF), N9 (I-UPF).
   *
   * Default: 4 interfaces
   * Valid range: [2, 16]
   *
   * @note Minimum 2 required (N3 + N6 at least)
   * @see 3GPP TS 23.501 Section 4.4.1 (UPF interfaces)
   */
  int_config_value m_max_upf_interfaces{};

  /**
   * @brief Maximum number of redirect interfaces
   *
   * Interfaces used for traffic redirection (e.g., for lawful intercept,
   * traffic mirroring, or service chaining).
   *
   * Default: 2 interfaces
   * Valid range: [1, 16]
   *
   * @note Must be ≤ max_upf_interfaces (validated in validate())
   * @see 3GPP TS 29.244 Section 8.2.25 (Redirect Information IE)
   */
  int_config_value m_max_upf_redirect_interfaces{};

  /**
   * @brief Maximum ARP table entries
   *
   * Size of the ARP cache for resolving MAC addresses on N6 interface.
   * Critical for performance to avoid ARP storms.
   *
   * Default: 256 entries
   * Valid range: [2, 4096]
   *
   * @note Should be sized based on number of data network hosts
   */
  int_config_value m_max_arp_entries{};

  /**
   * @brief Maximum application IDs per session
   *
   * Application Detection rules based on deep packet inspection.
   * Used for Application Function (AF) influence on traffic routing.
   *
   * Default: 8 IDs
   * Valid range: [0, 32]
   *
   * @note 3GPP Rel-16+ feature
   * @see 3GPP TS 29.244 Section 8.2.25 (Application ID)
   */
  int_config_value m_max_application_ids_per_session{};

  /**
   * @brief Maximum traffic endpoints per session
   *
   * Number of traffic endpoints (local F-TEIDs) that can be associated
   * with a PDU session for multi-access scenarios.
   *
   * Default: 2 endpoints
   * Valid range: [1, 4]
   *
   * @note 3GPP Rel-16+ feature for ATSSS (Access Traffic Steering/Switching)
   * @see 3GPP TS 29.244 Section 8.2.158 (Traffic Endpoint ID)
   */
  int_config_value m_max_traffic_endpoints_per_session{};

  /**
   * @brief Maximum Ethernet packet filters per session
   *
   * Packet filters for Ethernet PDU sessions (non-IP traffic).
   * Used with enable_eth_pdu feature.
   *
   * Default: 4 filters
   * Valid range: [0, 16]
   *
   * @note Only relevant if UPF_ENABLE_ETH_PDU feature is enabled
   * @see 3GPP TS 29.244 Section 8.2.66 (Ethernet Packet Filter)
   */
  int_config_value m_max_ethernet_packet_filters_per_session{};

  /**
   * @brief Maximum redundant transmission parameters per session
   *
   * Parameters for URLLC redundant transmission feature.
   * Typically 0 unless URLLC is explicitly configured.
   *
   * Default: 0 (disabled)
   * Valid range: [0, 4]
   *
   * @note 3GPP Rel-16+ URLLC feature
   * @see 3GPP TS 29.244 Section 8.2.179 (Redundant Transmission Parameters)
   */
  int_config_value m_max_redundant_transmission_params_per_session{};

 public:
  /**
   * @brief Construct with explicit configuration name
   *
   * Initializes all parameters with default values from UPF_DEFAULT_MAX_*
   * constants and sets up validation intervals based on 3GPP specifications.
   *
   * @param name Configuration section name (typically "datapath_configuration")
   *
   * @note All int_config_value members are initialized with both default values
   *       and validation ranges to ensure safe operation.
   * @note Default values are from basic_nrf_config_ebpf.yaml
   */
  explicit upf_datapath_configuration(const std::string& name);

  /**
   * @brief Default constructor (delegates to parameterized constructor)
   *
   * Convenience constructor that uses the standard configuration section name.
   * Implemented as a delegating constructor to ensure proper initialization.
   *
   * @note Equivalent to
   * upf_datapath_configuration(UPF_CONFIG_DATAPATH_CONFIGURATION)
   * @note This pattern ensures all members are properly initialized with
   * defaults
   */
  upf_datapath_configuration()
      : upf_datapath_configuration(UPF_CONFIG_DATAPATH_CONFIGURATION) {}

  /**
   * @brief Parse configuration from YAML node
   *
   * Reads datapath configuration parameters from the YAML node. If a parameter
   * is not present in the YAML, the default value (from constructor) is
   * retained.
   *
   * @param node YAML node containing datapath_configuration section
   *
   * @throws YAML::Exception If YAML parsing fails
   *
   * @note Parameters are validated after parsing via validate()
   * @note All parameters are optional in YAML - defaults are always available
   * @see validate()
   */
  void from_yaml(const YAML::Node& node) override;

  /**
   * @brief Convert configuration to string representation
   *
   * Generates a human-readable string representation of all configuration
   * parameters with their current values and validation status.
   *
   * @param indent Indentation prefix for formatting
   * @return Formatted string representation
   *
   * @note Useful for logging and debugging configuration state
   */
  [[nodiscard]] std::string to_string(const std::string& indent) const override;

  /**
   * @brief Serialize configuration to JSON
   *
   * Exports all configuration parameters to a JSON object for persistence
   * or API communication.
   *
   * @return JSON object containing all parameters
   *
   * @note Uses int_config_value::to_json() for each member
   */
  nlohmann::json to_json() override;

  /**
   * @brief Deserialize configuration from JSON
   *
   * Imports configuration parameters from a JSON object. Missing parameters
   * retain their default values.
   *
   * @param json_data JSON object containing configuration parameters
   * @return true if parsing succeeded, false otherwise
   *
   * @note Does not throw exceptions - returns false on parsing errors
   * @note validate() should be called after successful import
   */
  bool from_json(const nlohmann::json& json_data) override;

  /**
   * @brief Validate all configuration parameters
   *
   * Performs comprehensive validation including:
   * 1. Individual parameter range checks (via int_config_value validation)
   * 2. Cross-parameter validation (e.g., redirect ≤ total interfaces)
   * 3. Overflow prevention for derived BPF map sizes
   * 4. Logical consistency checks
   *
   * @throws std::runtime_error If any validation check fails
   * @throws std::overflow_error If derived map sizes would overflow uint32_t
   *
   * @warning This method MUST be called before using the configuration!
   * @warning Failing to call validate() may result in BPF map creation failures
   *
   * @section validation_checks Validation Checks Performed
   * - max_upf_redirect_interfaces ≤ max_upf_interfaces
   * - Total PDR map size = sessions × pdrs_per_session < 2^32
   * - Total FAR map size = sessions × fars_per_session < 2^32
   * - Total QER map size = sessions × qers_per_session < 2^32
   * - Total SDF filter map size calculation and validation
   * - Consistency between related parameters
   *
   * @note Range checks for individual parameters are performed by
   * int_config_value
   */
  void validate() override;

  /**
   * @brief Get maximum PFCP sessions
   * @return Maximum number of concurrent PFCP sessions [1, 100000]
   * @note Controls the main session lookup BPF map size
   */
  [[nodiscard]] int get_max_pdu_sessions() const;

  /**
   * @brief Get maximum PDRs per PDU session
   * @return Maximum Packet Detection Rules per session [1, 64]
   * @note Total PDR map size = sessions × this value
   */
  [[nodiscard]] int get_max_pdrs_per_pdu_session() const;

  /**
   * @brief Get maximum FARs per PDU session
   * @return Maximum Forwarding Action Rules per session [1, 64]
   * @note Total FAR map size = sessions × this value
   */
  [[nodiscard]] int get_max_fars_per_pdu_session() const;

  /**
   * @brief Get maximum QERs per PDU session
   * @return Maximum QoS Enforcement Rules per session [1, 32]
   * @note Only used if UPF_ENABLE_QOS is enabled
   */
  [[nodiscard]] int get_max_qers_per_pdu_session() const;

  /**
   * @brief Get maximum URRs per PDU session
   * @return Maximum Usage Reporting Rules per session [0, 16]
   * @note Only used if UPF_ENABLE_URR is enabled
   */
  [[nodiscard]] int get_max_urrs_per_pdu_session() const;

  /**
   * @brief Get maximum BARs per PDU session
   * @return Maximum Buffering Action Rules per session [0, 8]
   * @note Only used if UPF_ENABLE_BAR is enabled
   */
  [[nodiscard]] int get_max_bars_per_pdu_session() const;

  /**
   * @brief Get maximum SDF filters per PDU session
   * @return Maximum Service Data Flow filters per session [1, 32]
   * @note Each filter has maximum string length defined separately
   */
  [[nodiscard]] int get_max_sdf_filters_per_pdu_session() const;

  /**
   * @brief Get maximum SDF filter string length
   * @return Maximum buffer size for filter descriptions [64, 2048] bytes
   * @note Affects memory allocation for SDF filter parsing
   */
  [[nodiscard]] int get_max_sdf_filter_string_length() const;

  /**
   * @brief Get maximum UPF interfaces
   * @return Maximum number of network interfaces [2, 16]
   * @note Minimum 2 required (N3 + N6)
   */
  [[nodiscard]] int get_max_upf_interfaces() const;

  /**
   * @brief Get maximum redirect interfaces
   * @return Maximum number of redirect interfaces [1, 16]
   * @note Must be ≤ max_upf_interfaces (enforced by validate())
   */
  [[nodiscard]] int get_max_upf_redirect_interfaces() const;

  /**
   * @brief Get maximum ARP entries
   * @return Maximum ARP table size [2, 4096]
   * @note Should match expected number of hosts on N6 network
   */
  [[nodiscard]] int get_max_arp_entries() const;

  /**
   * @brief Get maximum application IDs per session
   * @return Maximum application detection IDs [0, 32]
   * @note 3GPP Rel-16+ feature for application-aware routing
   */
  [[nodiscard]] int get_max_application_ids_per_session() const;

  /**
   * @brief Get maximum traffic endpoints per session
   * @return Maximum traffic endpoints [1, 4]
   * @note 3GPP Rel-16+ feature for ATSSS (multi-access)
   */
  [[nodiscard]] int get_max_traffic_endpoints_per_session() const;

  /**
   * @brief Get maximum Ethernet packet filters per session
   * @return Maximum Ethernet filters [0, 16]
   * @note Only used if UPF_ENABLE_ETH_PDU is enabled
   */
  [[nodiscard]] int get_max_ethernet_packet_filters_per_session() const;

  /**
   * @brief Get maximum redundant transmission parameters per session
   * @return Maximum URLLC redundancy parameters [0, 4]
   * @note 3GPP Rel-16+ URLLC feature, typically 0
   */
  [[nodiscard]] int get_max_redundant_transmission_params_per_session() const;
};

//-----------------------------------------------------------------------------------------------
/**
 * @brief UPF Network Interface Configuration
 *
 * Configures a single network interface of the UPF (N3, N4, N6, or N9).
 * Extends local_interface with UPF-specific parameters like Network Instance
 * (NWI) and interface type.
 *
 * Each interface represents a 3GPP reference point:
 * - N3: Interface towards RAN (Radio Access Network)
 * - N4: Interface towards SMF (Session Management Function)
 * - N6: Interface towards Data Network (Internet/Enterprise)
 * - N9: Interface towards another UPF (for UL CL scenarios)
 *
 * @note Inherits host, port, and if_name from local_interface base class
 *
 * @see 3GPP TS 23.501 Section 4.4.1 for UPF interface definitions
 *
 * @section example Example Usage
 * @code
 * // Create N3 interface configuration
 * upf_interface_config n3(
 *     "N3", "192.168.70.134", 2152, "enp0s8", "N3");
 *
 * // Create N6 interface with NWI
 * upf_interface_config n6(
 *     "N6", "192.168.72.134", 0, "enp0s9", "N6", "internet");
 *
 * // Convert to NRF registration format
 * auto upf_info_item = n3.to_upf_info_item();
 * @endcode
 *
 * @author OpenAirInterface
 * @version 1.0
 */
class upf_interface_config : public local_interface {
 private:
  /**
   * @brief Network Instance (NWI) identifier
   *
   * Identifies the data network instance this interface connects to.
   * Used primarily on N6 interface to distinguish between different DNs
   * (e.g., "internet", "ims", "enterprise").
   *
   * Optional: Can be empty for interfaces without NWI (N3, N4, N9)
   *
   * @note NWI is used in NRF registration and session establishment
   * @see 3GPP TS 29.510 Section 6.1.6.2.9 (NFProfile with UPF info)
   */
  string_config_value m_nwi;

  /**
   * @brief Interface type (N3, N4, N6, or N9)
   *
   * Specifies which 3GPP reference point this interface implements.
   * Must match one of the standard types: "N3", "N4", "N6", "N9"
   *
   * Required field that determines the interface's role in the 5G system.
   *
   * @note Interface type affects:
   *       - Protocol used (GTP-U for N3/N9, PFCP for N4, IP for N6)
   *       - NRF registration information
   *       - Traffic handling rules
   */
  string_config_value m_interface_type;

 public:
  /**
   * @brief Construct interface configuration without NWI
   *
   * Creates an interface configuration for interfaces that don't require
   * Network Instance identification (typically N3, N4, N9).
   *
   * @param name Interface name (e.g., "N3", "N4", "N6")
   * @param host IP address or hostname of the interface
   * @param port Port number (2152 for GTP-U on N3/N9, 8805 for PFCP on N4, 0
   * for N6)
   * @param if_name Linux interface name (e.g., "eth0", "enp0s8")
   * @param if_type Interface type: "N3", "N4", "N6", or "N9"
   *
   * @note For N6 interfaces that connect to specific data networks,
   *       use the constructor with NWI parameter instead
   */
  explicit upf_interface_config(
      const std::string& name, const std::string& host, uint16_t port,
      const std::string& if_name, const std::string& if_type);

  /**
   * @brief Construct interface configuration with NWI
   *
   * Creates an interface configuration for N6 interfaces that connect to
   * specific data network instances requiring NWI identification.
   *
   * @param name Interface name (typically "N6")
   * @param host IP address or hostname of the interface
   * @param port Port number (typically 0 for N6)
   * @param if_name Linux interface name
   * @param if_type Interface type (typically "N6")
   * @param nwi Network Instance identifier (e.g., "internet", "ims",
   * "enterprise")
   *
   * @note NWI is included in UPF NRF registration and used for session routing
   */
  explicit upf_interface_config(
      const std::string& name, const std::string& host, uint16_t port,
      const std::string& if_name, const std::string& if_type,
      const std::string& nwi);

  /**
   * @brief Parse interface configuration from YAML
   *
   * Reads interface parameters from YAML node including inherited parameters
   * (host, port, if_name) and UPF-specific parameters (interface_type, nwi).
   *
   * @param node YAML node containing interface configuration
   *
   * @throws YAML::Exception If required parameters are missing or invalid
   *
   * @section yaml_example YAML Example
   * @code{.yaml}
   * interfaces:
   *   n3:
   *     host: 192.168.70.134
   *     port: 2152
   *     if_name: enp0s8
   *     interface_type: N3
   *   n6:
   *     host: 192.168.72.134
   *     port: 0
   *     if_name: enp0s9
   *     interface_type: N6
   *     nwi: internet
   * @endcode
   */
  void from_yaml(const YAML::Node& node) override;

  /**
   * @brief Set interface type
   *
   * Updates the interface type. Used when interface type is determined
   * after initial construction.
   *
   * @param if_type New interface type ("N3", "N4", "N6", or "N9")
   *
   * @note Changing interface type after configuration may require
   *       updating other dependent settings
   */
  void set_if_type(const std::string& if_type);

  /**
   * @brief Convert configuration to string representation
   *
   * Generates human-readable string showing all interface parameters.
   *
   * @param indent Indentation prefix for formatting
   * @return Formatted string with all interface parameters
   */
  [[nodiscard]] std::string to_string(const std::string& indent) const override;

  /**
   * @brief Convert to UPF Info Item for NRF registration
   *
   * Transforms the interface configuration into the format required for
   * UPF NRF registration (NFProfile).
   *
   * @return interface_upf_info_item_t structure for NRF registration
   *
   * @note This format is used when the UPF registers with NRF to advertise
   *       its available interfaces and supported data networks
   *
   * @see 3GPP TS 29.510 Section 6.1.6.2.9 (UPF NF Profile)
   */
  [[nodiscard]] interface_upf_info_item_t to_upf_info_item() const;

  /**
   * @brief Convert to internal interface configuration structure
   *
   * Transforms to the runtime interface configuration structure used
   * internally by the UPF application.
   *
   * @return interface_cfg_t structure for UPF runtime use
   *
   * @note This is the format used by upf_app for actual packet processing
   */
  [[nodiscard]] interface_cfg_t to_interface_config() const;
};

//-----------------------------------------------------------------------------------------------
/**
 * @brief UPF YAML Configuration Manager
 *
 * Main configuration class responsible for:
 * - Loading and parsing UPF configuration from YAML files
 * - Validating configuration parameters
 * - Converting between YAML and runtime configuration structures
 * - Providing default interface configurations
 * - Managing NRF address resolution
 *
 * This class orchestrates the entire configuration loading process, including:
 * - NF (Network Function) base configuration
 * - UPF-specific support features
 * - Datapath BPF map configuration
 * - Network interface configuration (N3, N4, N6, N9)
 * - NRF registration information
 *
 * @note This is the primary entry point for UPF configuration management.
 *       upf_app creates an instance of this class to load configuration at
 * startup.
 *
 * @see upf For the parsed UPF configuration structure
 * @see upf_config For the runtime configuration structure
 *
 * @section example Example Usage
 * @code
 * // Load configuration from file
 * upf_config_yaml yaml_cfg("/etc/oai/basic_nrf_config_ebpf.yaml", true, false);
 *
 * // Convert to runtime configuration
 * upf_config runtime_cfg;
 * yaml_cfg.to_upf_config(runtime_cfg);
 *
 * // Use runtime configuration
 * upf_app app(runtime_cfg);
 * @endcode
 *
 * @author OpenAirInterface
 * @version 1.0
 */
class upf_config_yaml : public config {
 public:
  /**
   * @brief Construct UPF configuration loader
   *
   * Initializes the configuration framework and loads the UPF configuration
   * from the specified YAML file.
   *
   * @param config_path Path to the YAML configuration file
   * @param log_stdout Enable logging to stdout
   * @param log_rot_file Enable rotating file logging
   *
   * @throws std::runtime_error If configuration file cannot be read or parsed
   * @throws YAML::Exception If YAML syntax is invalid
   *
   * @note Configuration is loaded and validated during construction
   */
  explicit upf_config_yaml(
      const std::string& config_path, bool log_stdout, bool log_rot_file);

  /**
   * @brief Destructor
   *
   * Cleans up configuration resources.
   */
  virtual ~upf_config_yaml();

  /**
   * @brief Resolve hostname to IP address
   *
   * Performs DNS resolution of hostnames to IPv4 addresses.
   * Used for resolving NF hostnames in the configuration.
   *
   * @param host Hostname or IP address string
   * @return Resolved IPv4 address as in_addr structure
   *
   * @throws std::runtime_error If hostname resolution fails
   *
   * @note If host is already an IP address, returns it directly
   * @note DNS resolution is synchronous and may block
   */
  static in_addr resolve_nf(const std::string& host);

  /**
   * @brief HTTP version for SBI communication
   *
   * Specifies the HTTP protocol version (1 or 2) used for Service-Based
   * Interface (SBI) communication with other 5GC NFs.
   *
   * Typical values:
   * - 1: HTTP/1.1
   * - 2: HTTP/2
   */
  unsigned int http_version;

  /**
   * @brief SBI Address Information
   *
   * Helper structure for managing Service-Based Interface address information
   * including IPv4 address, port, HTTP version, API version, and FQDN.
   *
   * @note This structure provides conversion methods from sbi_interface
   *       configuration with optional DNS resolution.
   */
  struct sbi_addr {
    /** @brief IPv4 address of the NF */
    struct in_addr ipv4_addr;

    /** @brief Port number for SBI communication */
    unsigned int port;

    /** @brief HTTP protocol version (1 or 2) */
    unsigned int http_version;

    /** @brief API version string (e.g., "v1") */
    std::string api_version;

    /** @brief Fully Qualified Domain Name */
    std::string fqdn;

    /**
     * @brief Convert from SBI interface with DNS resolution
     *
     * @param sbi_val SBI interface configuration
     * @param http_vers HTTP version to use
     *
     * @note This method performs DNS resolution of the host
     *
     * @deprecated TODO: Remove after refactoring calling classes
     */
    void from_sbi_config_type(const sbi_interface& sbi_val, int http_vers) {
      ipv4_addr    = resolve_nf(sbi_val.get_host());
      port         = sbi_val.get_port();
      http_version = http_vers;
      api_version  = sbi_val.get_api_version();
      fqdn         = sbi_val.get_host();
    }

    /**
     * @brief Convert from SBI interface without DNS resolution
     *
     * @param sbi_val SBI interface configuration
     * @param http_vers HTTP version to use
     *
     * @note This method does NOT perform DNS resolution
     *       Use when host is already an IP address or when resolution
     *       should be deferred
     */
    void from_sbi_config_type_no_resolving(
        const sbi_interface& sbi_val, int http_vers) {
      fqdn         = sbi_val.get_host();
      api_version  = sbi_val.get_api_version();
      port         = sbi_val.get_port();
      http_version = http_vers;
    }
  };

  /**
   * @brief NRF (Network Repository Function) address
   *
   * SBI address information for the NRF used by this UPF for:
   * - NF registration and deregistration
   * - NF discovery (finding SMF, AMF, etc.)
   * - Heartbeat/keepalive
   *
   * @note This is populated from the "nrf" section in YAML configuration
   */
  sbi_addr nrf_addr;

  /**
   * @brief Convert YAML configuration to runtime UPF configuration
   *
   * Transforms the parsed YAML configuration into the runtime upf_config
   * structure used by upf_app. This includes:
   * - Feature flags
   * - Datapath BPF map sizes
   * - Interface configurations
   * - PFCP session parameters
   *
   * @param cfg Output runtime configuration structure to populate
   *
   * @note This method must be called after successful YAML parsing
   * @note Validation is performed as part of the YAML parsing, not here
   *
   * @see upf_config For the runtime configuration structure
   */
  void to_upf_config(oai::config::upf_config& cfg);

  /**
   * @brief Pre-process configuration before use
   *
   * Performs any necessary preprocessing steps on the loaded configuration
   * such as:
   * - Computing derived values
   * - Resolving references between configuration sections
   * - Setting up default values for optional parameters
   *
   * @note Called automatically during configuration loading
   */
  void pre_process();

  /**
   * @brief Get default N3 interface configuration
   *
   * Returns a default configuration for the N3 interface (RAN-facing).
   * Used when N3 is not explicitly configured in YAML.
   *
   * Default N3 configuration:
   * - Host: 192.168.70.134
   * - Port: 2152 (GTP-U)
   * - Interface name: "enp0s8"
   * - Type: "N3"
   *
   * @return Default N3 interface configuration
   *
   * @note These defaults match typical OAI development environment setup
   */
  static upf_interface_config get_default_n3_interface();

  /**
   * @brief Get default N4 interface configuration
   *
   * Returns a default configuration for the N4 interface (SMF-facing).
   * Used when N4 is not explicitly configured in YAML.
   *
   * Default N4 configuration:
   * - Host: 192.168.70.134
   * - Port: 8805 (PFCP)
   * - Interface name: "enp0s8"
   * - Type: "N4"
   *
   * @return Default N4 interface configuration
   */
  static upf_interface_config get_default_n4_interface();

  /**
   * @brief Get default N6 interface configuration
   *
   * Returns a default configuration for the N6 interface (Data Network-facing).
   * Used when N6 is not explicitly configured in YAML.
   *
   * Default N6 configuration:
   * - Host: 192.168.72.134
   * - Port: 0 (not applicable for N6)
   * - Interface name: "enp0s9"
   * - Type: "N6"
   *
   * @return Default N6 interface configuration
   */
  static upf_interface_config get_default_n6_interface();
};

//-----------------------------------------------------------------------------------------------
/**
 * @brief UPF Network Function Configuration
 *
 * Main UPF configuration structure that aggregates all UPF-specific parameters
 * including support features, datapath configuration, interfaces, and NRF
 * registration information.
 *
 * This class inherits from nf (network function base) and adds UPF-specific
 * configuration elements:
 * - Instance ID for multi-UPF deployments
 * - Support features (BPF, QoS, URR, etc.)
 * - Datapath BPF map configuration
 * - Network interfaces (N3, N4, N6, N9)
 * - UPF Info for NRF registration
 * - Remote N6 gateway configuration
 * - Associated SMF list
 *
 * @note This class is the parsed representation of the YAML configuration.
 *       It is converted to upf_config (runtime structure) before use by
 * upf_app.
 *
 * @see upf_config_yaml For the YAML configuration manager
 * @see upf_config For the runtime configuration structure
 *
 * @section example Example Usage
 * @code
 * // Typically created by upf_config_yaml during YAML parsing
 * upf upf_cfg("UPF", "192.168.70.134", sbi, interfaces);
 * upf_cfg.from_yaml(yaml_node["upf"]);
 * upf_cfg.validate();
 *
 * // Access configuration
 * auto& features = upf_cfg.get_support_features();
 * auto& datapath = upf_cfg.get_datapath_configuration();
 * @endcode
 *
 * @author OpenAirInterface
 * @version 1.0
 */
class upf : public nf {
 private:
  /**
   * @brief UPF instance identifier
   *
   * Unique identifier for this UPF instance when multiple UPFs are deployed.
   * Used for:
   * - Distinguishing between UPF instances in logs
   * - NRF registration (as part of NF Instance ID)
   * - Load balancing and UPF selection
   *
   * Valid range: [0, 255]
   * Default: 0
   *
   * @note In single-UPF deployments, this is typically 0
   */
  int_config_value m_instance_id;

  /**
   * @brief UPF support features configuration
   *
   * Feature flags controlling which optional UPF capabilities are enabled:
   * - BPF datapath vs userspace
   * - QoS enforcement
   * - Usage reporting
   * - Buffering
   * - Multi-access routing
   * - Source NAT
   * - Framed routing
   * - Ethernet PDU sessions
   *
   * @see upf_support_features For detailed feature descriptions
   */
  upf_support_features m_upf_support_features;

  /**
   * @brief Datapath BPF map configuration
   *
   * Controls the sizing of all BPF maps used by the eBPF datapath including:
   * - PFCP session limits
   * - PDR/FAR/QER/URR/BAR rules per session
   * - SDF filter configuration
   * - Network interface limits
   * - ARP table size
   *
   * @see upf_datapath_configuration For detailed parameter descriptions
   */
  upf_datapath_configuration m_upf_datapath_configuration;

  /**
   * @brief UPF information for NRF registration
   *
   * Contains UPF-specific information advertised to NRF:
   * - Supported S-NSSAIs (network slices)
   * - DNN (Data Network Name) lists per slice
   * - Interface information (N3, N6, N9)
   * - TAI (Tracking Area Identity) list
   *
   * @note This structure is serialized to JSON for NRF registration
   * @see 3GPP TS 29.510 Section 6.1.6.2.9 (UPF NF Profile)
   */
  oai::model::nrf::UpfInfo m_upf_info;

  /**
   * @brief Remote N6 gateway address
   *
   * IPv4 address or hostname of the remote gateway on the N6 interface
   * (Data Network side). Used for routing internet-bound traffic.
   *
   * Optional: Can be empty if N6 gateway is auto-discovered or not needed.
   *
   * @note Typically used when UPF needs static routing to internet gateway
   */
  string_config_value m_remote_n6;

  /**
   * @brief List of associated SMFs
   *
   * List of SMF (Session Management Function) instances that this UPF
   * communicates with. Used for:
   * - Authorized SMF checking (security)
   * - Load balancing across SMFs
   * - Failover scenarios
   *
   * Optional: Empty list means accept connections from any SMF
   *
   * @note SMFs are identified by FQDN or IP address
   */
  std::vector<string_config_value> m_smf_list;

  /**
   * @brief Network interface configurations map
   *
   * Map of interface type (N3, N4, N6, N9) to interface configuration.
   * Allows flexible configuration of:
   * - Single interface per type (typical)
   * - Multiple interfaces with NWI differentiation (advanced)
   * - UL CL scenarios with multiple N6/N9 interfaces
   *
   * Key format: "N3", "N6", "N4", "N9", or "N6_<nwi>" for multi-NWI
   *
   * @note Map structure allows future extension for multiple interfaces
   *       of the same type (e.g., "N6_internet", "N6_ims")
   */
  std::map<std::string, upf_interface_config> m_interfaces;

  /**
   * @brief Create or update an interface configuration
   *
   * Helper method for YAML parsing that creates a new interface or updates
   * an existing one based on the YAML node content.
   *
   * @param iface_type Interface type ("n3", "n4", "n6", "n9")
   * @param node YAML node containing interface configuration
   * @param default_config Default configuration to use if not fully specified
   *
   * @note Handles case-insensitive interface type matching
   * @note Merges YAML values with default configuration
   */
  void create_or_update_interface(
      const std::string& iface_type, const YAML::Node& node,
      const upf_interface_config& default_config);

 public:
  /**
   * @brief Construct UPF configuration
   *
   * Initializes the UPF configuration with basic NF parameters and
   * interface map. This is typically called by upf_config_yaml during
   * configuration loading.
   *
   * @param name UPF instance name (typically "UPF" or "UPF-<region>")
   * @param host SBI host address for this UPF
   * @param sbi SBI interface configuration
   * @param interfaces Map of pre-configured interfaces (typically defaults)
   *
   * @note Support features are initialized to all-disabled by default
   * @note Datapath configuration is initialized with default values
   */
  explicit upf(
      const std::string& name, const std::string& host,
      const sbi_interface& sbi,
      const std::map<std::string, upf_interface_config>& interfaces);

  /**
   * @brief Parse UPF configuration from YAML
   *
   * Reads all UPF-specific configuration from the YAML node including:
   * - Instance ID
   * - Support features
   * - Datapath configuration
   * - UPF Info (S-NSSAI, DNN lists)
   * - Remote N6 gateway
   * - SMF list
   * - Interface configurations (N3, N4, N6, N9)
   *
   * @param node YAML node containing "upf" section
   *
   * @throws YAML::Exception If YAML parsing fails
   * @throws std::runtime_error If required parameters are missing
   *
   * @note Missing optional parameters retain their default values
   * @note validate() should be called after successful parsing
   */
  void from_yaml(const YAML::Node& node) override;

  /**
   * @brief Validate complete UPF configuration
   *
   * Performs comprehensive validation of all configuration parameters:
   * - NF base configuration (inherited)
   * - Support features validation
   * - Interface configuration validation
   * - UPF Info validation
   * - Datapath configuration validation (ranges, overflow checks)
   *
   * @throws std::runtime_error If any validation check fails
   *
   * @warning This method MUST be called before using the configuration!
   * @warning Failing to call validate() may result in runtime errors
   *
   * @note This is the final validation step before configuration is ready
   */
  void validate() override;

  /**
   * @brief Convert configuration to string representation
   *
   * Generates a human-readable string representation of the complete
   * UPF configuration including all subsections.
   *
   * @param indent Indentation prefix for formatting
   * @return Formatted multi-line string with full configuration
   *
   * @note Useful for logging configuration at startup
   * @note Output includes all nested configurations (features, datapath,
   * interfaces)
   */
  [[nodiscard]] std::string to_string(const std::string& indent) const override;

  /**
   * @brief Get UPF instance ID
   * @return Instance identifier [0-255]
   */
  [[nodiscard]] const uint32_t get_instance_id() const;

  /**
   * @brief Get remote N6 gateway address
   * @return Gateway IP address or hostname (may be empty)
   */
  [[nodiscard]] const std::string get_remote_n6() const;

  /**
   * @brief Get list of associated SMFs
   * @return Vector of SMF addresses (may be empty)
   */
  [[nodiscard]] const std::vector<string_config_value> get_smf_list() const;

  /**
   * @brief Get support features configuration
   * @return Reference to support features (feature flags)
   */
  [[nodiscard]] const upf_support_features& get_support_features() const;

  /**
   * @brief Get UPF Info for NRF registration
   * @return Reference to UPF Info structure
   */
  [[nodiscard]] const oai::model::nrf::UpfInfo& get_upf_info() const;

  /**
   * @brief Get datapath configuration
   * @return Reference to datapath BPF map configuration
   */
  [[nodiscard]] const upf_datapath_configuration& get_datapath_configuration()
      const;

  /**
   * @brief Get all interface configurations
   * @return Map of interface type to configuration
   */
  [[nodiscard]] const std::map<std::string, upf_interface_config>&
  get_interfaces() const;
};

}  // namespace oai::config
