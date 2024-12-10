//
// Created by root on 5/10/24.
//

#include "FramedRouting.hpp"
#include <utility>
#include <sstream>
#include <iostream>
#include <upf_config.hpp>

extern oai::config::upf_config upf_cfg;

namespace fr {

FramedRouting::FramedRouting(std::shared_ptr<LocalRouting> localRouting)
    : localRouting(std::move(localRouting)) {}

void FramedRouting::addFramedRoute(
    const uint32_t ue_ip, const pfcp::framed_route_s& framed_route_s) {
  std::stringstream ss(framed_route_s.framed_route);
  std::string ipsubnetmask;
  while (std::getline(ss, ipsubnetmask, this->pdi_fr_delimeter)) {
    std::pair<uint32_t, uint32_t> ipCidr = this->extractIPCidr(ipsubnetmask);
    auto key                             = createFramedRoutingKey(ipCidr);
    auto routing_info = createLocalRoutingInformation(ipCidr);
    auto snat_info    = createLocalSnatInformation(ipCidr);
    this->KeyToIp.insert({key, ue_ip});
    localRouting->add_route(routing_info);
    localRouting->add_source_snat(snat_info);
  }
}

uint32_t FramedRouting::retrieveUEIp(const uint32_t destination_ip) const {
  for (uint32_t i = 32; i > 0; --i) {
    FramedRoutingKey framedRoutingKey =
        createFramedRoutingKey({destination_ip, i});

    auto ip = this->KeyToIp.find(framedRoutingKey);

    if (ip != KeyToIp.end()) {
      return ip->second;
    };
  };
  return 0;
};

uint32_t FramedRouting::retrieveUEIp(
    const pfcp::framed_route_s& framed_route_s) const {
  std::stringstream ss(framed_route_s.framed_route);
  std::string ipsubnetmask;

  while (std::getline(ss, ipsubnetmask, this->pdi_fr_delimeter)) {
    std::pair<uint32_t, uint32_t> ipCidr = this->extractIPCidr(ipsubnetmask);
    FramedRoutingKey framedRoutingKey =
        createFramedRoutingKey({ipCidr.first, ipCidr.second});
    auto ip = this->KeyToIp.find(framedRoutingKey);
    if (ip != KeyToIp.end()) {
      return ip->second;
    }
  }
  return 0;
}
void FramedRouting::remove_entry(uint32_t ue_ip) {
  for (uint32_t i = 32; i > 0; --i) {
    FramedRoutingKey framedRoutingKey = createFramedRoutingKey({ue_ip, i});
    auto ip                           = this->KeyToIp.find(framedRoutingKey);
    if (ip != KeyToIp.end()) {
      this->KeyToIp.erase(ip);
      this->localRouting->delete_route(ip->second);
    };
  };
}

std::pair<uint32_t, uint32_t> FramedRouting::extractIPCidr(
    const std::string& fr_subnet) {
  const char subnet_delimeter = '/';
  std::string ipSubnet        = fr_subnet;
  uint32_t ip                 = 0;
  uint32_t cidr               = 0;

  const std::string ip_substring =
      ipSubnet.substr(0, ipSubnet.find(subnet_delimeter));
  ip = framedIPToUeIP(ip_substring);

  std::reverse(ipSubnet.begin(), ipSubnet.end());
  std::string subnet_substring =
      ipSubnet.substr(0, ipSubnet.rfind(subnet_delimeter));
  cidr = frameSubnetToUInt(subnet_substring);
  return std::pair<uint32_t, uint32_t>{ip, cidr};
}

FramedRoutingKey FramedRouting::createFramedRoutingKey(
    const std::pair<uint32_t, uint32_t> ipCidr) const {
  const uint32_t ipv4Size      = 32;
  const uint32_t subnet_adress = 0xffffffff << (ipv4Size - ipCidr.second);
  const uint32_t networkAdress = subnet_adress & ipCidr.first;
  return FramedRoutingKey{networkAdress, subnet_adress};
}

RoutingInformation FramedRouting::createLocalRoutingInformation(
    const std::pair<uint32_t, uint32_t>& ipCidr) const {
  struct in_addr addr;
  addr.s_addr             = htonl(ipCidr.first);
  std::string destination = inet_ntoa(addr);
  uint32_t netmask        = ipCidr.second;
  std::string device      = "tun0";
  // todo (phine.tech) use correct DNN
  struct in_addr address4_gw = {};
  address4_gw.s_addr         = upf_cfg.pdns[0].network_ipv4.s_addr + be32toh(1);
  std::string gateway_address = inet_ntoa(address4_gw);

  return fr::RoutingInformation{destination, netmask, device, gateway_address};
}

SourceNatInformation FramedRouting::createLocalSnatInformation(
    const std::pair<uint32_t, uint32_t>& ipCidr) const {
  struct in_addr addr;
  addr.s_addr              = htonl(ipCidr.first);
  std::string destination  = inet_ntoa(addr);
  uint32_t netmask         = ipCidr.second;
  std::string device       = upf_cfg.n6.if_name;
  std::string snat_address = oai::utils::conv::toString(upf_cfg.n6.addr4);

  return SourceNatInformation{destination, netmask, device, snat_address};
}

}  // namespace fr