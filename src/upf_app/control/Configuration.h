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
  static std::string gtp_interface_;            ///< N3 GTP-U interface
  static std::string udp_interface_;            ///< N6 Data Network interface
  static unsigned char is_socket_buffer_enabled_; ///< Socket buffer flag
};

#endif  // CONFIGURATION_H_
