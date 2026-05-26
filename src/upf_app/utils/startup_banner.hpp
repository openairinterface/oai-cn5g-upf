/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_STARTUP_BANNER_HPP_SEEN
#define FILE_STARTUP_BANNER_HPP_SEEN

#include <string>
#include <vector>
#include <cstdint>

namespace oai::config {
class upf_config;
}

struct QosFlowInfo {
  uint32_t qer_id;
  uint8_t qfi;
  uint32_t rate_kbps;  // GBR (Guaranteed Bit Rate)
  uint32_t ceil_kbps;  // MBR (Maximum Bit Rate)
  uint16_t class_id;   // TC class ID (minor number)
  std::string flow_description;
};

/**
 * @brief Display startup banner with version information
 */
void DisplayStartupBanner();

/**
 * @brief Display concise configuration summary
 * @param cfg UPF configuration
 */
void DisplayConfigSummary(const oai::config::upf_config& cfg);

/**
 * @brief Display network interface configuration
 * @param cfg UPF configuration
 */
void DisplayNetworkInterfaces(const oai::config::upf_config& cfg);

/**
 * @brief Display data plane status and BPF maps
 * @param cfg UPF configuration
 */
void DisplayDataPlaneStatus(const oai::config::upf_config& cfg);

/**
 * @brief Display XDP/TC configuration summary
 *
 * Shows XDP modes (Native/SKB) and BPF statistics
 */
void DisplayXdpConfiguration(
    const oai::config::upf_config& cfg, const std::string& n3_xdp_mode,
    const std::string& n6_xdp_mode, size_t total_maps);

/**
 * @brief Display ready message
 */
void DisplayReadyMessage();

/**
 * @brief Display QoS flows in a compact table format
 *
 * @param seid Session ID
 * @param qos_flows Vector of QoS flow information
 */
void DisplayQosFlowTable(
    uint64_t seid, const std::vector<QosFlowInfo>& qos_flows);

/**
 * @brief Display QoS setup start banner
 *
 * @param seid Session ID
 * @param interface Network interface name
 */
void LogQosSetupStart(uint64_t seid, const std::string& interface);

/**
 * @brief Display QoS setup completion banner
 *
 * @param seid Session ID
 * @param num_qos_flows Number of QoS flows configured
 * @param has_errors Whether any errors occurred during setup
 */
void LogQosSetupComplete(uint64_t seid, int num_qos_flows, bool has_errors);

#endif /* FILE_STARTUP_BANNER_HPP_SEEN */