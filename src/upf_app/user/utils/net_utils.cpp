/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */
#include "net_utils.hpp"
#include <ifaddrs.h>
#include <net/if.h>
#include "logger.hpp"
#include "helpers/GetNicInformation.hpp"

namespace oai::utils::net {

//---------------------------------------------------------------------------------------------------------------
int count_available_interfaces() {
  int num_ifaces         = 0;
  struct ifaddrs* ifaddr = nullptr;

  if (getifaddrs(&ifaddr) == 0) {
    for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
      if (ifa->ifa_addr && (ifa->ifa_flags & IFF_UP)) ++num_ifaces;
    }
    freeifaddrs(ifaddr);
  } else {
    Logger::upf_app().warn("Unable to enumerate network interfaces");
  }
  return num_ifaces;
}

//---------------------------------------------------------------------------------------------------------------
bool interface_exists(const std::string& ifname) {
  return if_nametoindex(ifname.c_str()) != 0;
}

//---------------------------------------------------------------------------------------------------------------
int get_interface_index(const std::string& ifname) {
  return static_cast<int>(if_nametoindex(ifname.c_str()));
}

}  // namespace oai::utils::net
