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

  // todo(kw) create a facade for fr options.

 private:
  const char pdi_fr_delimeter = ' ';

  // todo(kw) discuss size or use constant
  std::shared_ptr<LocalRouting> localRouting;
  std::unordered_map<FramedRoutingKey, uint32_t> KeyToIp{};

  [[nodiscard]] uint32_t framedIPToUeIP(const std::string& ip) const;

  [[nodiscard]] uint32_t frameSubnetToUInt(std::string& subnet) const;

  [[nodiscard]] std::pair<uint32_t, uint32_t> extractIPCidr(
      const std::string& fr_subnet) const;

  [[nodiscard]] FramedRoutingKey createFramedRoutingKey(
      std::pair<uint32_t, uint32_t> ipCidr) const;

  [[nodiscard]] RoutingInformation createLocalRoutingInformation(
      const std::pair<uint32_t, uint32_t>& ipCidr) const;

  [[nodiscard]] SourceNatInformation createLocalSnatInformation(
      const std::pair<uint32_t, uint32_t>& ipCidr) const;
};

}  // namespace fr
