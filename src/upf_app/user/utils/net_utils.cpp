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
 * @file net_utils.cpp
 * @brief Implementation of network interface utilities
 * @author OpenAirInterface
 * @date 2025
 */

#include "net_utils.hpp"
#include <ifaddrs.h>
#include <net/if.h>
#include "logger.hpp"

namespace oai {
namespace utils {
namespace net {

//------------------------------------------------------------------------------
int CountAvailableInterfaces() {
  int num_interfaces     = 0;
  struct ifaddrs* ifaddr = nullptr;

  // Get list of all interfaces
  if (getifaddrs(&ifaddr) == 0) {
    // Iterate through interface list
    for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
      // Count only interfaces that are UP and have an address
      if (ifa->ifa_addr && (ifa->ifa_flags & IFF_UP)) {
        ++num_interfaces;
      }
    }
    freeifaddrs(ifaddr);
  } else {
    Logger::upf_app().warn(
        "Unable to enumerate network interfaces (getifaddrs failed)");
  }

  Logger::upf_app().debug(
      "Found %d active network interfaces", num_interfaces);
  return num_interfaces;
}

//------------------------------------------------------------------------------
bool InterfaceExists(const std::string& interface_name) {
  // if_nametoindex returns 0 if interface doesn't exist
  unsigned int if_index = if_nametoindex(interface_name.c_str());
  return (if_index != 0);
}

//------------------------------------------------------------------------------
int GetInterfaceIndex(const std::string& interface_name) {
  // if_nametoindex returns 0 if interface doesn't exist
  unsigned int if_index = if_nametoindex(interface_name.c_str());

  if (if_index == 0) {
    Logger::upf_app().warn(
        "Interface '%s' not found", interface_name.c_str());
  }

  return static_cast<int>(if_index);
}

}  // namespace net
}  // namespace utils
}  // namespace oai
