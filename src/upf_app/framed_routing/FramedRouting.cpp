//
// Created by root on 5/10/24.
//

#include "FramedRouting.hpp"

namespace fr {


    void FramedRouting::addFramedRoute(
            const uint32_t ue_ip, const pfcp::framed_route_s& framed_route_s) {
        std::stringstream ss(framed_route_s.framed_route);
        // todo make configuratable?
        const char delimiter = ',';
        std::string ipsubnetmask;
        while (std::getline(ss, ipsubnetmask, delimiter)) {
            // todo(kw) 32 bit? to lazy to calculate but FramedRoutingKey could be 32bit
            // and networkAdress too.
            std::pair<uint32_t, uint32_t> ipCidr = this->extractIPCidr(ipsubnetmask);
            auto key                             = CreateFramedRoutingKey(ipCidr);
            this->KeyToIp.insert({key, ue_ip});
        }
    }

uint32_t FramedRouting::retrieveFramedUEIp(
    const uint32_t destination_ip) const {
  for (uint32_t i = 32; i > 0; --i) {
    FramedRoutingKey framedRoutingKey =
        CreateFramedRoutingKey({destination_ip, i});
    auto ip = this->KeyToIp.find(framedRoutingKey);
    if (ip != KeyToIp.end()) {
      return ip->second;
    };
  };
  return 0;
};

void FramedRouting::removeEntry(uint32_t ue_ip) {
  for (uint32_t i = 32; i > 0; --i) {
    FramedRoutingKey framedRoutingKey = CreateFramedRoutingKey({ue_ip, i});
    auto ip                           = this->KeyToIp.find(framedRoutingKey);
    if (ip != KeyToIp.end()) {
      this->KeyToIp.erase(ip);
    };
  };
}


uint32_t FramedRouting::framedIPToUeIP(const std::string& ip) const {
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
}

uint32_t FramedRouting::frameSubnetToUInt(std::string& subnet) const {
  // todo be a method?
  std::string temp_subnet = "";
  for (auto i = subnet.length(); i > 0; i--) {
    temp_subnet.push_back(subnet.at(i - 1));
  }
  return std::stoi(temp_subnet);
}

std::pair<uint32_t, uint32_t> FramedRouting::extractIPCidr(
    const std::string& fr_subnet) const {
  const char subnet_delimeter = '/';
  std::string ipSubnet        = fr_subnet;
  uint32_t ip                 = 0;
  uint32_t cidr               = 0;

  const std::string ip_substring =
      ipSubnet.substr(0, ipSubnet.find(subnet_delimeter));
  ip = this->framedIPToUeIP(ip_substring);
  std::string ip_temp;

  std::reverse(ipSubnet.begin(), ipSubnet.end());
  std::string dns_substring =
      ipSubnet.substr(0, ipSubnet.rfind(subnet_delimeter));
  cidr = this->frameSubnetToUInt(dns_substring);
  return std::pair<uint32_t, uint32_t>{ip, cidr};
}

FramedRoutingKey FramedRouting::CreateFramedRoutingKey(
    const std::pair<uint32_t, uint32_t> ipCidr) const {
  const uint32_t ipv4Size      = 32;
  const uint32_t subnet_adress = 0xffffffff << (ipv4Size - ipCidr.second);
  const uint32_t networkAdress = subnet_adress & ipCidr.first;
  return FramedRoutingKey{networkAdress, subnet_adress};
}

}  // namespace fr