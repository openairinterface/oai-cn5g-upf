//
// Created by root on 7/22/24.
//

#include <fmt/format.h>
#include <arpa/inet.h>
#include "LocalRouting.hpp"

namespace fr {

bool LocalRouting::addRoute(const RoutingInformation& routing_information) {
  auto cmd = fmt::format(
      "ip route add {}/{} via {} dev tun0", routing_information.destination,
      routing_information.netmask, routing_information.gateway_address);
  auto rc = system((const char*) cmd.c_str());
  if (rc == 0) {
      this->routeInfoToRtEntry.insert({routing_information.destination,routing_information});
    return true;
  }
  return false;
}

bool LocalRouting::deleteRoute(const uint32_t& network_address) {
  // todo(phine.tech) create function remove dublicated_code
  struct in_addr addr;
  addr.s_addr                = htonl(network_address);
  std::string destination    = inet_ntoa(addr);
  auto routing_info_iterator = this->routeInfoToRtEntry.find(destination);
  if (routing_info_iterator != routeInfoToRtEntry.end()) {
    const auto routing_information = routing_info_iterator->second;
    auto cmd                       = fmt::format(
        "ip route del {}/{} via {} dev tun0", routing_information.destination,
        routing_information.netmask, routing_information.gateway_address);
    auto rc = system((const char*) cmd.c_str());
    if (rc == 0) {
      return true;
    }
    return false;
  }
  return false;
};
}  // namespace fr