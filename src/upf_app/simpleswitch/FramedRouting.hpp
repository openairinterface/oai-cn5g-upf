/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include <cstdint>
#include <memory>
#include <vector>
#include "FramedRoutingHash.h"
#include "pfcp_pdr.hpp"
#include "LocalRouting.hpp"

// Defined in the BPF header framed_routing_bpf.h (kernel/include). Only
// forward-declared here so this widely-included header does not force every
// consumer onto the BPF include path; the full type is pulled in by the .cpp
// (FramedRouting.cpp) and by the BPF-datapath caller (SessionProgramManager).
struct FramedRoutingKeyBPF;

namespace fr {

class FramedRouting {
 public:
  FramedRouting() = delete;

  explicit FramedRouting(std::shared_ptr<LocalRouting> localRouting);

  virtual ~FramedRouting() = default;

  [[nodiscard]] uint32_t retrieveUEIp(const uint32_t destination_ip) const;

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

  /**
   * @brief Extract the destination prefix from an RFC 2865 Framed-Route value.
   *
   * Per 3GPP TS 29.244 §8.2.109 the Framed-Route IE carries the value part of
   * the RFC 2865 Framed-Route AVP, whose text is
   *   "<destination>[/<prefix-length>] [<gateway>] [<metric> ...]".
   * Each IE describes exactly ONE route; a list of routes is a list of IEs.
   * Only the destination field is significant for UPF routing — the gateway
   * and metric are ignored (TS 29.244 §5.16 NOTE 7: routes are announced
   * regardless of Framed-Routing). Returns {ip(host-order), cidr}, or {0,0}
   * when empty/unparseable (prefix-length defaults to /32 if omitted).
   */
  [[nodiscard]] static std::pair<uint32_t, uint32_t> parseFramedRouteDest(
      const pfcp::framed_route_s& framed_route_s);

  /**
   * @brief Parse a Framed-Route IE into its BPF-datapath keys.
   *
   * One key per whitespace-separated sub-route, host-order numeric — the exact
   * value the XDP session-lookup fallback (resolve_framed_session) hashes. Used
   * by the BPF datapath to populate m_framed_route_mapping. The simpleswitch
   * datapath uses addFramedRoute()/LocalRouting instead.
   */
  [[nodiscard]] static std::vector<FramedRoutingKeyBPF> toBpfKeys(
      const pfcp::framed_route_s& framed_route_s);

 private:
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
