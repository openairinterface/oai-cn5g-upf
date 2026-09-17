/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "sdf_filter.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <cstdlib>
#include <cstring>
#include <sstream>
#include <vector>

#include "logger.hpp"

namespace oai::upf {

namespace {

/// "any" | "assigned" | a.b.c.d | a.b.c.d/len
bool parse_addr(
    const std::string& tok, bool& any, bool& assigned, uint32_t& addr,
    uint32_t& mask) {
  any = assigned = false;
  if (tok == "any") {
    any = true;
    return true;
  }
  if (tok == "assigned") {
    assigned = true;
    return true;
  }

  std::string ip   = tok;
  int prefix       = 32;
  const auto slash = tok.find('/');
  if (slash != std::string::npos) {
    ip            = tok.substr(0, slash);
    const char* p = tok.c_str() + slash + 1;
    char* end     = nullptr;
    const long v  = strtol(p, &end, 10);
    if (end == p || *end != '\0' || v < 0 || v > 32) return false;
    prefix = (int) v;
  }
  struct in_addr a = {};
  if (inet_pton(AF_INET, ip.c_str(), &a) != 1) return false;
  addr = a.s_addr;
  mask = prefix == 0 ? 0 : htonl(0xFFFFFFFFu << (32 - prefix));
  return true;
}

/// "5000" | "5000-5010". A comma list is deliberately refused rather than
/// half-honoured; see sdf_compile()'s contract.
bool parse_ports(const std::string& tok, uint16_t& lo, uint16_t& hi) {
  const char* s = tok.c_str();
  char* end     = nullptr;
  const long a  = strtol(s, &end, 10);
  if (end == s || a < 0 || a > 65535) return false;
  if (*end == '\0') {
    lo = hi = (uint16_t) a;
    return true;
  }
  if (*end != '-') return false;
  const char* s2 = end + 1;
  const long b   = strtol(s2, &end, 10);
  if (end == s2 || *end != '\0' || b < a || b > 65535) return false;
  lo = (uint16_t) a;
  hi = (uint16_t) b;
  return true;
}

/// "ip" (any) | a name we know | a number
bool parse_proto(const std::string& tok, bool& any, uint8_t& proto) {
  any = false;
  if (tok == "ip") {
    any = true;
    return true;
  }
  if (tok == "tcp") {
    proto = IPPROTO_TCP;
    return true;
  }
  if (tok == "udp") {
    proto = IPPROTO_UDP;
    return true;
  }
  if (tok == "icmp") {
    proto = IPPROTO_ICMP;
    return true;
  }
  if (tok == "sctp") {
    proto = IPPROTO_SCTP;
    return true;
  }
  const char* s = tok.c_str();
  char* end     = nullptr;
  const long v  = strtol(s, &end, 10);
  if (end == s || *end != '\0' || v < 0 || v > 255) return false;
  proto = (uint8_t) v;
  return true;
}

bool parse(const std::string& fd, sdf_rule& r) {
  std::vector<std::string> t;
  {
    std::istringstream is(fd);
    std::string w;
    while (is >> w) t.push_back(w);
  }
  // The shortest legal form is seven tokens:
  //   permit out ip from any to assigned
  if (t.size() < 7) return false;

  size_t i = 0;
  // "deny" has no meaning for a PDI -- a PDR either detects a packet or it
  // does not, and there is no third outcome to express. Refusing it leaves
  // the packet to the next PDR rather than inverting the rule.
  if (t[i] != "permit") return false;
  ++i;
  if (t[i] == "out") {
    r.out = true;
  } else if (t[i] == "in") {
    r.out = false;
  } else {
    return false;
  }
  ++i;
  if (!parse_proto(t[i], r.any_proto, r.proto)) return false;
  ++i;
  if (t[i] != "from") return false;
  ++i;
  if (!parse_addr(t[i], r.src_any, r.src_assigned, r.src_addr, r.src_mask))
    return false;
  ++i;
  if (i < t.size() && t[i] != "to") {
    if (!parse_ports(t[i], r.src_lo, r.src_hi)) return false;
    r.has_src_ports = true;
    ++i;
  }
  if (i >= t.size() || t[i] != "to") return false;
  ++i;
  if (i >= t.size()) return false;
  if (!parse_addr(t[i], r.dst_any, r.dst_assigned, r.dst_addr, r.dst_mask))
    return false;
  ++i;
  if (i < t.size()) {
    if (!parse_ports(t[i], r.dst_lo, r.dst_hi)) return false;
    r.has_dst_ports = true;
    ++i;
  }
  // Trailing options (fragment, ipoptions, tcpflags, ...) narrow the rule.
  // Ignoring one would widen what this PDR catches, so refuse instead.
  return i == t.size();
}

inline bool addr_ok(
    bool any, bool assigned, uint32_t addr, uint32_t mask, uint32_t pkt,
    uint32_t ue_ip) {
  if (any) return true;
  if (assigned) return pkt == ue_ip;
  return (pkt & mask) == (addr & mask);
}

}  // namespace

//------------------------------------------------------------------------------
sdf_rule sdf_compile(const std::string& flow_description) {
  sdf_rule r;
  if (flow_description.empty()) return r;
  r.present = true;
  r.valid   = parse(flow_description, r);
  if (!r.valid)
    Logger::pfcp_switch().warn(
        "SDF filter not understood, its PDR will match nothing: \"%s\"",
        flow_description.c_str());
  return r;
}

//------------------------------------------------------------------------------
bool sdf_match(
    const sdf_rule& r, const struct iphdr* iph, const std::size_t len,
    const bool uplink, const uint32_t ue_ip) {
  if (!r.present) return true;
  if (!r.valid) return false;

  if (!r.any_proto && iph->protocol != r.proto) return false;

  // A rule is written for one direction. Travelling the other way the
  // endpoints swap: "to assigned 5000" downlink is "from assigned 5000"
  // uplink. The SMF commonly sends the same description in both the uplink
  // and the downlink PDR, so mirroring here is what lets the uplink one match
  // at all.
  const bool mirror  = (r.out == uplink);
  const uint32_t src = mirror ? iph->daddr : iph->saddr;
  const uint32_t dst = mirror ? iph->saddr : iph->daddr;

  if (!addr_ok(r.src_any, r.src_assigned, r.src_addr, r.src_mask, src, ue_ip))
    return false;
  if (!addr_ok(r.dst_any, r.dst_assigned, r.dst_addr, r.dst_mask, dst, ue_ip))
    return false;

  if (!r.has_src_ports && !r.has_dst_ports) return true;

  // Ports live in the L4 header, which a non-first fragment does not carry.
  if (iph->frag_off & htons(0x1FFF)) return false;
  if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP &&
      iph->protocol != IPPROTO_SCTP)
    return false;

  const std::size_t ihl = (std::size_t) iph->ihl * 4;
  if (len < ihl + 4) return false;
  const uint8_t* l4 = (const uint8_t*) iph + ihl;
  uint16_t sport = 0, dport = 0;
  memcpy(&sport, l4, sizeof(sport));
  memcpy(&dport, l4 + 2, sizeof(dport));
  sport = ntohs(sport);
  dport = ntohs(dport);

  const uint16_t rsp = mirror ? dport : sport;
  const uint16_t rdp = mirror ? sport : dport;
  if (r.has_src_ports && (rsp < r.src_lo || rsp > r.src_hi)) return false;
  if (r.has_dst_ports && (rdp < r.dst_lo || rdp > r.dst_hi)) return false;
  return true;
}

}  // namespace oai::upf
