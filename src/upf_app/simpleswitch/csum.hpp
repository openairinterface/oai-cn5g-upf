/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_CSUM_HPP_SEEN
#define FILE_CSUM_HPP_SEEN

#include <arpa/inet.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace oai::upf::app {

/**
 * @brief Ones-complement sum of @p len bytes, continuing from @p sum.
 *
 * Eight bytes an iteration, with the carry out of the top folded back into the
 * bottom as it happens. The two-bytes-at-a-time version this replaced did four
 * times as many additions per segment, which matters because TSO moved this
 * work into the datapath: the UPF now checksums every segment it builds.
 *
 * This is plain portable C++, relying on memcpy for unaligned access. It is
 * not a port of any architecture-specific routine and makes no claim to match
 * one; if this ever shows up in a profile, that is where to look next.
 *
 * The sum is taken over 16-bit words read in memory order, so on a
 * little-endian host the accumulator holds a byte-swapped value throughout.
 * That is deliberate and cancels out: csum_fold() writes the result back in
 * the same order. Widening the lanes does not disturb it, because folding the
 * accumulator in halves adds the lanes together and the ones-complement sum is
 * invariant under 16-bit rotation.
 */
inline uint32_t csum_partial(const void* p, size_t len, uint32_t sum) {
  const auto* b = (const uint8_t*) p;
  uint64_t acc  = sum;

  while (len >= 8) {
    uint64_t w;
    memcpy(&w, b, 8);
    acc += w;
    if (acc < w) acc++;  // carry wraps round, as ones-complement requires
    b += 8;
    len -= 8;
  }
  if (len >= 4) {
    uint32_t w;
    memcpy(&w, b, 4);
    acc += w;
    if (acc < w) acc++;
    b += 4;
    len -= 4;
  }
  if (len >= 2) {
    uint16_t w;
    memcpy(&w, b, 2);
    acc += w;
    if (acc < w) acc++;
    b += 2;
    len -= 2;
  }
  if (len) {
    const uint64_t w = *b;  // odd trailing byte, already in network order
    acc += w;
    if (acc < w) acc++;
  }

  while (acc >> 32) acc = (acc & 0xFFFFFFFFu) + (acc >> 32);
  return (uint32_t) acc;
}

inline uint16_t csum_fold(uint32_t sum) {
  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
  return (uint16_t) ~sum;
}

/// IPv4 header checksum, over the header only (§RFC 791).
inline void ip_csum_set(struct iphdr* iph) {
  iph->check = 0;
  iph->check = csum_fold(csum_partial(iph, (size_t) iph->ihl * 4, 0));
}

/// TCP checksum over the pseudo-header plus the segment (§RFC 793).
inline void tcp_csum_set(struct iphdr* iph, size_t l4_len) {
  auto* th   = (struct tcphdr*) ((uint8_t*) iph + (size_t) iph->ihl * 4);
  th->check  = 0;
  uint32_t s = 0;
  s          = csum_partial(&iph->saddr, 4, s);
  s          = csum_partial(&iph->daddr, 4, s);
  const uint16_t proto_be = htons(IPPROTO_TCP);
  const uint16_t len_be   = htons((uint16_t) l4_len);
  s                       = csum_partial(&proto_be, 2, s);
  s                       = csum_partial(&len_be, 2, s);
  s                       = csum_partial(th, l4_len, s);
  th->check               = csum_fold(s);
}

/**
 * @brief Finish a checksum the kernel deliberately left incomplete.
 *
 * TUN_F_CSUM has to be advertised to get TSO, and it also stops the kernel
 * checksumming the packets it does *not* split. Those arrive with NEEDS_CSUM
 * set and the two bytes at csum_start+csum_offset holding the pseudo-header
 * sum instead of a finished checksum. Forwarding one unchanged puts a packet
 * on the air that every receiver counts as a bad segment and discards.
 *
 * That partial sum lies inside the range being summed, so summing
 * [csum_start, end) and folding picks it up: the field must be read as part of
 * the data, never cleared first.
 */
inline void vnet_complete_csum(
    char* pkt, size_t plen, uint16_t csum_start, uint16_t csum_offset) {
  const size_t at = (size_t) csum_start + csum_offset;
  if (csum_start >= plen || at + sizeof(uint16_t) > plen) return;  // malformed
  const uint16_t c =
      csum_fold(csum_partial(pkt + csum_start, plen - csum_start, 0));
  memcpy(pkt + at, &c, sizeof(c));
}

}  // namespace oai::upf::app

#endif /* FILE_CSUM_HPP_SEEN */
