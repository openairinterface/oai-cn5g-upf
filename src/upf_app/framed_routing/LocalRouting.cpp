//
// Created by root on 7/22/24.
//

#include <fmt/format.h>
#include <arpa/inet.h>
#include <iostream>
#include <logger.hpp>
#include "LocalRouting.hpp"

namespace fr {

void LocalRouting::add_route(const RoutingInformation& routing_information) {
  auto original_cerr_streambuf = std::cerr.rdbuf(nullptr);
  auto cmd                     = fmt::format(
      "ip route add {}/{} via {} dev tun0", routing_information.destination,
      routing_information.netmask, routing_information.gateway_address);
  auto rc = system((const char*) cmd.c_str());
  if (rc == 0) {
    Logger::pfcp_switch().info("Route created");
    this->routeInfoToRtEntry.insert(
        {routing_information.destination, routing_information});
  } else {
    Logger::pfcp_switch().warn("Route information not correct or does exists!");
  }
}

void LocalRouting::delete_route(const uint32_t& network_address) {
  // todo(phine.tech) create function remove dublicated_code
  auto original_cerr_streambuf = std::cerr.rdbuf(nullptr);
  std::string destination      = convert_s_addr_to_string(network_address);
  auto routing_info_iterator   = this->routeInfoToRtEntry.find(destination);
  if (routing_info_iterator != routeInfoToRtEntry.end()) {
    const auto routing_information = routing_info_iterator->second;
    auto cmd                       = fmt::format(
        "ip route del {}/{} via {} dev tun0", routing_information.destination,
        routing_information.netmask, routing_information.gateway_address);
    const auto rc = system((const char*) cmd.c_str());
    if (rc == 0) {
      Logger::pfcp_switch().info("Route deleted");
    } else {
      Logger::pfcp_switch().warn(
          "Route information not correct or does not exists!");
    }
  }
};

void LocalRouting::add_source_snat(
    const SourceNatInformation& source_nat_information) {
  const std::string cmd = fmt::format(
      "iptables -t nat -A POSTROUTING -s {}/{} -o {} -j SNAT --to "
      "{}",
      source_nat_information.destination, source_nat_information.netmask,
      source_nat_information.device, source_nat_information.snat_address);
  const auto rc = system((const char*) cmd.c_str());
  if (rc == 0) {
    Logger::pfcp_switch().info("Source NAT added");
  } else {
    Logger::pfcp_switch().warn("Source NAT not correct or does exists!");
  }
}

void LocalRouting::delete_ssnat(const uint32_t& network_address) {}

std::string LocalRouting::convert_s_addr_to_string(
    const uint32_t& network_address) {
  struct in_addr addr;
  addr.s_addr = htonl(network_address);
  return inet_ntoa(addr);
}
}  // namespace fr