//
// Created by root on 5/10/24.
//

#pragma once

#include <cstdint>
#include <memory>
#include <vector>
#include "FramedRoutingHash.h"
#include "pfcp_pdr.hpp"
#include "LocalRouting.hpp"

namespace fr {

class FramedRouting {
 public:
  FramedRouting() = delete;

  explicit FramedRouting(std::shared_ptr<LocalRouting> localRouting);

  virtual ~FramedRouting() = default;

  [[nodiscard]] uint32_t retrieveUEIp(const uint32_t destination_ip) const;

  [[nodiscard]] uint32_t retrieveUEIp(
      const pfcp::framed_route_s& framed_route_s) const;

  void addFramedRoute(
      uint32_t ue_ip, const pfcp::framed_route_s& framed_route_s);

  void remove_entry(uint32_t ue_ip);

  [[nodiscard]] static uint32_t framedIPToUeIP(const std::string& ip) {
    const char delimeter = '.';
    uint32_t result      = 0;
    int shift_counter    = 24;
    std::string ip_temp;
    for (auto i = 0; i < ip.length(); ++i) {
      ip_temp += ip.at(i);
      if (ip.at(i) == delimeter || i == ip.length() - 1) {
        result  = result | (std::stoi(ip_temp) << shift_counter);
        ip_temp = "";
        shift_counter -= 8;
      }
    }
    return result;
  };

  [[nodiscard]] static uint32_t frameSubnetToUInt(std::string& subnet) {
    std::string temp_subnet = "";
    if (subnet.length() > 2) {
      return 32;
    }
    for (auto i = subnet.length(); i > 0; i--) {
      temp_subnet.push_back(subnet.at(i - 1));
    }
    return std::stoi(temp_subnet);
  };

  [[nodiscard]] static std::pair<uint32_t, uint32_t> extractIPCidr(
      const std::string& fr_subnet);

 private:
  const char pdi_fr_delimeter = ' ';

  std::shared_ptr<LocalRouting> localRouting;
  std::unordered_map<FramedRoutingKey, uint32_t> KeyToIp{};

  [[nodiscard]] FramedRoutingKey createFramedRoutingKey(
      std::pair<uint32_t, uint32_t> ipCidr) const;

  [[nodiscard]] RoutingInformation createLocalRoutingInformation(
      const std::pair<uint32_t, uint32_t>& ipCidr) const;

  [[nodiscard]] SourceNatInformation createLocalSnatInformation(
      const std::pair<uint32_t, uint32_t>& ipCidr) const;
};

}  // namespace fr
