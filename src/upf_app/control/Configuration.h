/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef CONFIGURATION_H_
#define CONFIGURATION_H_

#include <string>

#include "upf_network_config.h"

/**
 * @class Configuration
 * @brief UPF system configuration manager.
 *
 * Static-member class that owns the N3/N6 interface name strings and
 * exposes BuildNetworkConfig() as the single write-point into
 * upf::g_net_cfg.
 */

class Configuration {
 public:
  /**
   * @brief Constructor — applies optional CLI argv overrides.
   *
   * If argc >= 3, argv[1] overrides the N3 interface name and argv[2]
   * overrides the N6 interface name.  The actual upf::g_net_cfg
   * population happens in BuildNetworkConfig(), not here.
   *
   * Must be called after upf_cfg has been fully loaded (i.e. after
   * config-file parsing in main()).
   *
   * @param argc Argument count from main().
   * @param argv Argument vector (argv[1] = N3 iface, argv[2] = N6 iface).
   */
  Configuration(int argc, char** argv);

  // ==========================================================================
  // Interface name accessors (legacy — prefer upf::GetN3Iface() for new code)
  // ==========================================================================

  /**
   * @brief Get N3 (GTP-U) interface name.
   * @return N3 interface name string.
   * @see upf::GetN3Iface() in upf_network_config.h
   */
  static std::string GetGTPInterface() { return gtp_interface_; }

  /**
   * @brief Get N6 (Data Network) interface name.
   * @return N6 interface name string.
   * @see upf::GetN6Iface() in upf_network_config.h
   */
  static std::string GetNonGTPInterface() { return non_gtp_interface_; }

  /**
   * @brief Check if socket buffer is enabled.
   * @return true if enabled.
   */
  static bool IsSocketBufferEnabled() { return is_socket_buffer_enabled_; }

  /**
   * @brief Populate upf::g_net_cfg from the OAI upf_config (YAML-parsed).
   *
   * Single write-point for all upf_cfg → upf::g_net_cfg field transfers.
   * Must be called before any BPF program load, BPF map sizing, or
   * feature-flag decision.  Called by UserPlaneComponent::Setup() as its
   * very first action.
   */
  static void BuildNetworkConfig();

 private:
  static std::string gtp_interface_;      ///< N3 GTP-U interface name
  static std::string non_gtp_interface_;  ///< N6 Data Network interface name
  static unsigned char is_socket_buffer_enabled_;  ///< Socket buffer flag
};

#endif  // CONFIGURATION_H_
