/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/**
 * @file Configuration.h
 * @brief System Configuration Management for UPF
 * @author OpenAirInterface
 * @date 2025
 *
 * Manages UPF configuration parameters including network interfaces,
 * feature flags, and system settings.
 */

#ifndef CONFIGURATION_H_
#define CONFIGURATION_H_

#include <string>

/**
 * @class Configuration
 * @brief UPF system configuration manager
 *
 * Handles configuration from command-line arguments and config files.
 *
 * @note Follows Google C++ Style Guide
 */
class Configuration {
 public:
  /**
   * @brief Constructor with command-line arguments
   * @param argc Argument count
   * @param argv Argument vector
   */
  Configuration(int argc, char** argv);

  /**
   * @brief Get GTP-U interface name (N3)
   * @return GTP interface name
   */
  static std::string GetGTPInterface() { return gtp_interface_; }

  /**
   * @brief Get UDP interface name (N6)
   * @return UDP interface name
   */
  static std::string GetUDPInterface() { return udp_interface_; }

  /**
   * @brief Check if socket buffer is enabled
   * @return true if enabled
   */
  static bool IsSocketBufferEnabled() { return is_socket_buffer_enabled_; }

 private:
  static std::string gtp_interface_;  ///< N3 GTP-U interface
  static std::string udp_interface_;  ///< N6 Data Network interface
  static unsigned char is_socket_buffer_enabled_;  ///< Socket buffer flag
};

#endif  // CONFIGURATION_H_
