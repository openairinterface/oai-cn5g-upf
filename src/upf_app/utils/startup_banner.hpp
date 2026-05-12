/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_STARTUP_BANNER_HPP_SEEN
#define FILE_STARTUP_BANNER_HPP_SEEN

#include <cstdint>
#include <string>
#include <vector>
#include "upf_pipeline_config.h"  // PipelineFeatureFlags, PduSessionType, ProgIndex

struct QosFlowInfo {
  uint32_t qer_id;
  uint8_t qfi;
  uint32_t rate_kbps;  ///< GBR (Guaranteed Bit Rate)
  uint32_t ceil_kbps;  ///< MBR (Maximum Bit Rate)
  uint16_t class_id;   ///< TC class ID (minor number)
  std::string flow_description;
};

// ==========================================================================
// Startup sequence banners
// All functions read network/feature config from upf::g_net_cfg directly.
// Must be called after Configuration::BuildNetworkConfig().
// ==========================================================================

/**
 * @brief Display program creation tree (called from upf_xdp_user after Step 2)
 * @param flags Pipeline feature flags
 */
void DisplayPipelineCreationTree(const PipelineFeatureFlags& flags);

/**
 * @brief Per-program load info for the load tree display
 */
struct ProgramLoadInfo {
  std::string name;   ///< Program class name
  size_t map_count;   ///< Number of BPF maps
  std::string iface;  ///< Interface name (entry programs only)
  bool is_tc;         ///< true for TC-BPF programs
  bool is_child;      ///< true for QERTCProgram (child of QERProgram)
};

/**
 * @brief Display program load tree with map counts (called from UPF_XDPProgram
 *        after all programs are loaded)
 * @param programs  Ordered list of program load info
 */
void DisplayPipelineLoadTree(const std::vector<ProgramLoadInfo>& programs);

/**
 * @brief Display full data-path call flow and architecture diagram
 * @param flags Pipeline feature flags (only enabled programs are drawn)
 */
void DisplayDataPathArchitecture(const PipelineFeatureFlags& flags);

/** @brief Display startup banner with version information */
void DisplayStartupBanner();

/** @brief Display concise configuration summary (reads upf::g_net_cfg) */
void DisplayConfigSummary();

/** @brief Display N3/N4/N6 network interface table (reads upf::g_net_cfg) */
void DisplayNetworkInterfaces();

/**
 * @brief Display feature flags and BPF map capacity table
 *        (reads upf::g_net_cfg)
 */
void DisplayDataPlaneStatus();

/**
 * @brief Display BPF tail-call pipeline configuration
 *
 * Shows which entry programs are loaded, which optional stages are enabled,
 * and their PROG_ARRAY slot assignments.
 *
 * @param flags  Pipeline feature flags built by UserPlaneComponent
 */
void DisplayPipelineConfig(const PipelineFeatureFlags& flags);

/**
 * @brief Display XDP/TC runtime configuration
 *
 * @param n3_xdp_mode  XDP mode string for N3 ("Native (Hardware)" or "SKB")
 * @param n6_xdp_mode  XDP mode string for N6
 * @param total_maps   Total number of BPF maps loaded
 */
void DisplayXdpConfiguration(
    const std::string& n3_xdp_mode, const std::string& n6_xdp_mode,
    size_t total_maps);

/** @brief Display final ready message */
void DisplayReadyMessage();

// ==========================================================================
// Per-session QoS banners
// ==========================================================================

/**
 * @brief Display QoS flows in a compact table format
 * @param seid      Session ID
 * @param qos_flows Vector of QoS flow information
 */
void DisplayQosFlowTable(
    uint64_t seid, const std::vector<QosFlowInfo>& qos_flows);

/**
 * @brief Display QoS setup start banner
 * @param seid       Session ID
 * @param interface  Network interface name
 */
void LogQosSetupStart(uint64_t seid, const std::string& interface);

/**
 * @brief Display QoS setup completion banner
 * @param seid          Session ID
 * @param num_qos_flows Number of QoS flows configured
 * @param has_errors    Whether any errors occurred during setup
 */
void LogQosSetupComplete(uint64_t seid, int num_qos_flows, bool has_errors);

#endif /* FILE_STARTUP_BANNER_HPP_SEEN */
