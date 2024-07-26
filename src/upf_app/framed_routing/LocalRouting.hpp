//
// Created by root on 7/22/24.
//

#pragma once

#include <memory>
#include <string>
#include <unordered_map>

namespace fr {
struct RoutingInformation {
  std::string destination;
  uint32_t netmask = 0;
  std::string device;
  std::string gateway_address;
};

struct SourceNatInformation {
  std::string destination;
  uint32_t netmask = 0;
  std::string device;
  std::string snat_address;
};
// todo (kw) rename class
class LocalRouting {
 public:
  virtual void add_route(const RoutingInformation& routing_information);

  virtual void delete_route(const uint32_t& network_address);

  virtual void add_source_snat(
      const SourceNatInformation& source_nat_information);

  // todo(phine.tech) implement delete if needed
  virtual void delete_ssnat(const uint32_t& network_address);

 private:
  std::unordered_map<std::string, RoutingInformation> routeInfoToRtEntry{};

  std::string convert_s_addr_to_string(const uint32_t& network_address);
};

}  // namespace fr
