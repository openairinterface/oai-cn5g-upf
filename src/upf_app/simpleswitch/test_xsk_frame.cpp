/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 *
 * Self-check for the AF_XDP frame parser. Header-only:
 *
 *   g++ -std=c++17 -O2 src/upf_app/simpleswitch/test_xsk_frame.cpp \
 *       -o /tmp/test_xsk_frame && /tmp/test_xsk_frame
 *
 * The frames come from the data network, and what the parser returns is
 * copied into the DL buffer and later walked by the lookup, which trusts the
 * IPv4 header lengths. So the cases that matter are the lies: an IHL below the
 * minimum, a Total Length shorter than the header, or longer than the frame.
 */

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <vector>

#include "xsk_frame.hpp"

using oai::upf::xsk_ipv4_span;

namespace {

/// A real Ethernet + IPv4/ICMP echo request (84 B of IP), padded with
/// `padding` trailing bytes like a NIC may deliver.
std::vector<uint8_t> icmp_frame(size_t padding = 0) {
  std::vector<uint8_t> f = {
      // Ethernet: dst, src, EtherType IPv4
      0x02, 0x42, 0xc0, 0xa8, 0x46, 0x86, 0x02, 0x42, 0xc0, 0xa8, 0x46, 0x01,
      0x08, 0x00,
      // IPv4: v4 IHL 5, ToS 0, tot_len 84, id, DF, TTL 64, ICMP, checksum
      0x45, 0x00, 0x00, 0x54, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x01, 0x8c, 0x5b,
      // src 192.168.70.1, dst 12.1.1.2
      0xc0, 0xa8, 0x46, 0x01, 0x0c, 0x01, 0x01, 0x02,
      // ICMP echo request: type 8, code 0, checksum, id, seq
      0x08, 0x00, 0xf7, 0xff, 0x00, 0x01, 0x00, 0x01};
  // 56 B of ICMP payload, so tot_len = 20 + 8 + 56 = 84.
  for (int i = 0; i < 56; ++i) f.push_back((uint8_t) i);
  for (size_t i = 0; i < padding; ++i) f.push_back(0);
  return f;
}

void set_tot_len(std::vector<uint8_t>& f, uint16_t v) {
  f[14 + 2] = (uint8_t) (v >> 8);
  f[14 + 3] = (uint8_t) (v & 0xff);
}

/// An IHL below 5 is not an IPv4 header; the lookup would read options that
/// are really the payload.
void test_ihl_below_5_rejected() {
  auto f = icmp_frame();
  f[14]  = 0x44;
  assert(!xsk_ipv4_span(f.data(), f.size()) && "IHL 4 is rejected");
  f[14] = 0x40;
  assert(!xsk_ipv4_span(f.data(), f.size()) && "IHL 0 is rejected");
}

/// A Total Length shorter than the header it claims to include is a lie.
void test_tot_len_below_header_rejected() {
  auto f = icmp_frame();
  set_tot_len(f, 19);
  assert(!xsk_ipv4_span(f.data(), f.size()) && "tot_len < 20 is rejected");
  f[14] = 0x46;  // IHL 6: 24 B of header
  set_tot_len(f, 23);
  assert(!xsk_ipv4_span(f.data(), f.size()) && "tot_len < IHL*4 is rejected");
  set_tot_len(f, 24);
  assert(xsk_ipv4_span(f.data(), f.size()) && "tot_len == IHL*4 is accepted");
}

/// The span is the IPv4 packet: it starts right after the Ethernet header and
/// ends at tot_len, so trailing padding is not buffered or replayed.
void test_eth_ipv4_span_starts_at_ip_header() {
  auto f   = icmp_frame(6);
  auto pkt = xsk_ipv4_span(f.data(), f.size());
  assert(pkt && "a well-formed ICMP frame is accepted");
  assert(pkt.data == f.data() + 14 && "span starts at the IPv4 header");
  assert(pkt.len == 84 && "span length is tot_len, not the frame length");
  assert(pkt.data[9] == 1 && pkt.data[20] == 8 && "it is the ICMP echo");

  auto exact = icmp_frame();
  auto p2    = xsk_ipv4_span(exact.data(), exact.size());
  assert(p2 && p2.len == exact.size() - 14 && "unpadded frame, whole packet");
}

/// ARP, IPv6 and anything else that is not EtherType 0x0800 is dropped.
void test_non_ip_ethertype_rejected() {
  auto f = icmp_frame();
  f[12]  = 0x08;
  f[13]  = 0x06;  // ARP
  assert(!xsk_ipv4_span(f.data(), f.size()) && "ARP is rejected");
  f[12] = 0x86;
  f[13] = 0xdd;  // IPv6
  assert(!xsk_ipv4_span(f.data(), f.size()) && "EtherType IPv6 is rejected");
  f[12] = 0x81;
  f[13] = 0x00;  // 802.1Q
  assert(!xsk_ipv4_span(f.data(), f.size()) && "a VLAN tag is rejected");
}

/// EtherType says IPv4 but the header does not: dropped.
void test_ipv6_or_bad_version_rejected() {
  auto f = icmp_frame();
  f[14]  = 0x65;  // version 6
  assert(!xsk_ipv4_span(f.data(), f.size()) && "version 6 is rejected");
  f[14] = 0x05;  // version 0
  assert(!xsk_ipv4_span(f.data(), f.size()) && "version 0 is rejected");
  f[14] = 0xf5;  // version 15
  assert(!xsk_ipv4_span(f.data(), f.size()) && "version 15 is rejected");
}

/// Anything shorter than Ethernet + a minimal IPv4 header is not read at all.
void test_short_frame_rejected() {
  auto f = icmp_frame();
  assert(!xsk_ipv4_span(f.data(), 33) && "33 bytes is too short");
  assert(!xsk_ipv4_span(f.data(), 13) && "13 bytes: not even Ethernet");
  assert(!xsk_ipv4_span(f.data(), 0) && "empty frame");
  assert(!xsk_ipv4_span(nullptr, 100) && "no frame");
  // 34 bytes with tot_len 20 is the smallest valid packet.
  set_tot_len(f, 20);
  auto p = xsk_ipv4_span(f.data(), 34);
  assert(p && p.len == 20 && "34 bytes with tot_len 20 is accepted");
}

/// A Total Length beyond the frame would make the lookup and the replay read
/// past the buffer: the over-read this parser exists to stop.
void test_tot_len_beyond_frame_rejected() {
  auto f = icmp_frame();
  set_tot_len(f, 85);
  assert(!xsk_ipv4_span(f.data(), f.size()) && "one byte past the frame");
  set_tot_len(f, 0xffff);
  assert(!xsk_ipv4_span(f.data(), f.size()) && "65535 past the frame");
  set_tot_len(f, 84);
  assert(!xsk_ipv4_span(f.data(), f.size() - 1) && "frame cut short by one");
}

}  // namespace

int main() {
  test_ihl_below_5_rejected();
  test_tot_len_below_header_rejected();
  test_eth_ipv4_span_starts_at_ip_header();
  test_non_ip_ethertype_rejected();
  test_ipv6_or_bad_version_rejected();
  test_short_frame_rejected();
  test_tot_len_beyond_frame_rejected();
  printf("xsk_frame: ok\n");
  return 0;
}
