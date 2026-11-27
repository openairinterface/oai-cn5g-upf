/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "FramedRouting.hpp"
#include "framed_routing_bpf.h"  // FramedRoutingKeyBPF, framed_routing_key_for_ip_cidr
#include <arpa/inet.h>
#include <algorithm>
#include <cctype>
#include <utility>
#include <sstream>
#include <iostream>
#include <logger.hpp>
#include <upf_config.hpp>

extern oai::config::upf_config upf_cfg;

namespace fr {

FramedRouting::FramedRouting(std::shared_ptr<LocalRouting> localRouting)
    : localRouting(std::move(localRouting)) {}

std::pair<uint32_t, uint32_t> FramedRouting::parseFramedRouteDest(
    const pfcp::framed_route_s& framed_route_s) {
  // RFC 2865 §5.22 Framed-Route text: "<dest>[/<len>] [<gateway>] [<metric>]".
  // Take only the first whitespace-separated field (the destination); the
  // operator>> stops at the first whitespace, so gateway/metric are dropped.
  std::stringstream ss(framed_route_s.framed_route);
  std::string dest;
  ss >> dest;
  if (dest.empty()) return {0, 0};
  return extractIPCidr(dest);
}

void FramedRouting::addFramedRoute(
    const uint32_t ue_ip, const pfcp::framed_route_s& framed_route_s) {
  // One Framed-Route IE == one route (TS 29.244 §8.2.109).
  const std::pair<uint32_t, uint32_t> ipCidr =
      parseFramedRouteDest(framed_route_s);
  if (ipCidr.second == 0) return;  // empty / unparseable / default route (/0)

  const auto key          = createFramedRoutingKey(ipCidr);
  const auto routing_info = createLocalRoutingInformation(ipCidr);
  const auto snat_info    = createLocalSnatInformation(ipCidr);
  this->KeyToIp.insert({key, ue_ip});
  localRouting->add_route(routing_info);
  localRouting->add_source_snat(snat_info);
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
  // The Framed-Route IE is operator-supplied text arriving over N4, so it may
  // be malformed. Nothing here throws: a bad route is reported as {0, 0},
  // which both callers (addFramedRoute and toBpfKeys) treat as "skip this
  // route", instead of failing the whole session.
  const std::string::size_type slash = fr_subnet.find('/');
  const std::string addr_str         = fr_subnet.substr(0, slash);

  // inet_pton accepts exactly four decimal octets in 0..255, so "300.1.1.1",
  // "10.1.1", "-1.0.0.0" and trailing garbage are all rejected.
  struct in_addr addr = {};
  if (inet_pton(AF_INET, addr_str.c_str(), &addr) != 1) {
    Logger::upf_app().warn(
        "Framed-Route '%s' has an invalid IPv4 address - route ignored",
        fr_subnet.c_str());
    return {0, 0};
  }

  // Prefix length: absent means a host route (/32); otherwise 1-2 decimal
  // digits in 1..32. The key derivation computes 0xffffffff << (32 - cidr),
  // so cidr == 0 or cidr > 32 would be an undefined shift. /0 is excluded
  // deliberately as well: a default route through a UE is not something this
  // datapath should install.
  uint32_t cidr = 32;
  if (slash != std::string::npos) {
    const std::string len_str = fr_subnet.substr(slash + 1);
    const bool digits_only =
        !len_str.empty() && len_str.size() <= 2 &&
        std::all_of(len_str.begin(), len_str.end(), [](unsigned char c) {
          return std::isdigit(c);
        });
    cidr = digits_only ? static_cast<uint32_t>(std::stoul(len_str)) : 0;
    if (cidr < 1 || cidr > 32) {
      Logger::upf_app().warn(
          "Framed-Route '%s' has an invalid prefix length "
          "(expected /1../32) - route ignored",
          fr_subnet.c_str());
      return {0, 0};
    }
  }

  return std::pair<uint32_t, uint32_t>{ntohl(addr.s_addr), cidr};
}

std::vector<FramedRoutingKeyBPF> FramedRouting::toBpfKeys(
    const pfcp::framed_route_s& framed_route_s) {
  // One Framed-Route IE == one route (TS 29.244 §8.2.109); return its single
  // BPF key. host-order numeric prefix + CIDR — identical math to the XDP
  // helper.
  std::vector<FramedRoutingKeyBPF> keys;
  const std::pair<uint32_t, uint32_t> ipCidr =
      parseFramedRouteDest(framed_route_s);
  if (ipCidr.second != 0) {
    keys.push_back(framed_routing_key_for_ip_cidr(ipCidr.first, ipCidr.second));
  }
  return keys;
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