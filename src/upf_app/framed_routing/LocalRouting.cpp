//
// Created by root on 7/22/24.
//

#include <fmt/format.h>
#include <arpa/inet.h>
#include <iostream>
#include <logger.hpp>
#include "LocalRouting.hpp"

namespace fr {

void LocalRouting::addRoute(const RoutingInformation& routing_information) {
    auto original_cerr_streambuf = std::cerr.rdbuf(nullptr );
  auto cmd = fmt::format(
      "ip route add {}/{} via {} dev tun0", routing_information.destination,
      routing_information.netmask, routing_information.gateway_address);
  auto rc = system((const char*) cmd.c_str());
    if (rc == 0) {
        Logger::pfcp_switch().info(
                "Route deleted");
      this->routeInfoToRtEntry.insert({routing_information.destination,routing_information});
  }
    Logger::pfcp_switch().warn(
            "Route information not correct or does not exists!");
}

void LocalRouting::deleteRoute(const uint32_t& network_address) {
  // todo(phine.tech) create function remove dublicated_code
    auto original_cerr_streambuf = std::cerr.rdbuf(nullptr );
    struct in_addr addr;
  addr.s_addr                = htonl(network_address);
  std::string destination    = inet_ntoa(addr);
  auto routing_info_iterator = this->routeInfoToRtEntry.find(destination);
  if (routing_info_iterator != routeInfoToRtEntry.end()) {
    const auto routing_information = routing_info_iterator->second;
    auto cmd                       = fmt::format(
        "ip route del {}/{} via {} dev tun0", routing_information.destination,
        routing_information.netmask, routing_information.gateway_address);
    auto rc = system((const char*) cmd.c_str() );
    if (rc == 0) {
        Logger::pfcp_switch().info(
                "Route deleted");
    }
      Logger::pfcp_switch().warn(
              "Route information not correct or does not exists!");
  }
};
}  // namespace fr