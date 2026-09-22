/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef DPDK_EAL_H_
#define DPDK_EAL_H_

#include <string>
#include <vector>

#include "upf_config.hpp"

/**
 * @class DpdkEal
 * @brief Brings up the DPDK Environment Abstraction Layer from upf_cfg.dpdk.
 *
 * Init() must run before any other DPDK call and before the UPF starts its
 * control threads: rte_eal_init() pins the calling thread to the main lcore,
 * and every thread created afterwards inherits that affinity. Init() therefore
 * restores an affinity mask for the calling thread that excludes the packet
 * lcores, so ITTI and the SBI threads keep away from the fast path.
 */
class DpdkEal {
 public:
  /**
   * @brief Build the EAL arguments from the configuration and initialise EAL.
   * @throws std::runtime_error if EAL initialisation fails.
   */
  static void Init(const oai::config::dpdk_cfg_t& config);

  /// Release EAL resources. Safe to call when Init() never ran.
  static void Cleanup();

  static bool IsInitialized() { return initialized_; }

  /**
   * @brief Expand an EAL corelist ("0-3", "1,2", "0-2,5") into lcore ids.
   * @throws std::runtime_error on malformed input.
   */
  static std::vector<unsigned> ParseCoreList(const std::string& core_list);

 private:
  /// Keep the control threads off the lcores that poll the NICs.
  static void RestoreControlThreadAffinity(
      const oai::config::dpdk_cfg_t& config);

  static bool initialized_;
};

#endif  // DPDK_EAL_H_
