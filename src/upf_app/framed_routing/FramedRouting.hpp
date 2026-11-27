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

  /**
   * @brief Parse "<a.b.c.d>[/<len>]" into {ip (host order), prefix length}.
   *
   * Strict: the address must be a dotted-quad IPv4 address (inet_pton) and the
   * prefix length, when present, 1 to 2 decimal digits in 1..32; a missing
   * prefix length means /32. Returns {0, 0} for anything else.
   */
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
   * One key per Framed-Route IE (empty if unparseable), host-order numeric —
   * the exact value the XDP session-lookup fallback (resolve_framed_session)
   * hashes. Used by the BPF datapath to populate m_framed_route_mapping. The
   * simpleswitch datapath uses addFramedRoute()/LocalRouting instead.
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
