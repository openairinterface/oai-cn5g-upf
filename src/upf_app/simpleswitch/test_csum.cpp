/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 *
 * Self-check for the checksum helpers. Header-only:
 *
 *   g++ -std=c++17 -O2 src/upf_app/simpleswitch/test_csum.cpp \
 *       -o /tmp/test_csum && /tmp/test_csum
 *
 * csum_partial() sums eight bytes an iteration instead of two. That is a
 * rewrite of the one routine every segment this datapath builds depends on,
 * and a checksum that is wrong is invisible here and fatal on the air -- the
 * receiver simply discards the packet. So the fast version is checked against
 * a plain two-bytes-at-a-time reference over every length and alignment that
 * can occur, rather than against a handful of expected constants.
 */

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "csum.hpp"

using oai::upf::app::csum_fold;
using oai::upf::app::csum_partial;
using oai::upf::app::ip_csum_set;
using oai::upf::app::tcp_csum_set;

namespace {

/// The implementation this replaced, kept as the oracle.
uint32_t csum_reference(const void* p, size_t len, uint32_t sum) {
  const auto* b = (const uint8_t*) p;
  while (len > 1) {
    uint16_t w;
    memcpy(&w, b, 2);
    sum += w;
    b += 2;
    len -= 2;
  }
  if (len) sum += *b;
  return sum;
}

}  // namespace

int main() {
  srand(1);  // fixed seed: a failure has to be reproducible

  // --- fast vs reference, every length and offset that can occur ----------
  // Folded, because the accumulators legitimately differ before folding: the
  // fast one has already wrapped its carries, the reference has not. What has
  // to match is the checksum that goes on the wire.
  std::vector<uint8_t> buf(4096);
  for (auto& c : buf) c = (uint8_t) (rand() & 0xff);

  size_t cases = 0;
  for (size_t off = 0; off < 8; off++) {       // every start alignment
    for (size_t len = 0; len <= 600; len++) {  // every length, odd included
      // Seeds a real call can carry: zero, or a part-accumulated
      // pseudo-header. Not 0xFFFFFFFF -- see the saturation case below.
      for (uint32_t seed : {0u, 1u, 0xFFFFu, 0x1234u, 0x1FFFEu}) {
        const uint16_t fast = csum_fold(csum_partial(&buf[off], len, seed));
        const uint16_t ref  = csum_fold(csum_reference(&buf[off], len, seed));
        assert(fast == ref);
        ++cases;
      }
    }
  }

  // --- a long buffer, where the 64-bit accumulator has to wrap -------------
  for (size_t len : {1024u, 1460u, 2048u, 4000u}) {
    const uint16_t fast = csum_fold(csum_partial(buf.data(), len, 0));
    const uint16_t ref  = csum_fold(csum_reference(buf.data(), len, 0));
    assert(fast == ref);
    ++cases;
  }

  // --- where the reference is the one that is wrong -----------------------
  // Adding to an accumulator that has already reached 0xFFFFFFFF overflows 32
  // bits, and ones-complement requires that carry to wrap into the bottom. The
  // old accumulator dropped it. Unreachable with real packets -- 64 kB sums to
  // about 2^31 -- but the property has to hold, so it is pinned here rather
  // than left to a reference that gets it wrong.
  //
  // 0xFFFFFFFF and 0xFFFF are the same value folded, so they must agree.
  {
    const uint8_t one = 0x67;
    assert(
        csum_fold(csum_partial(&one, 1, 0xFFFFFFFFu)) ==
        csum_fold(csum_partial(&one, 1, 0xFFFFu)));
    assert(
        csum_fold(csum_partial(buf.data(), 64, 0xFFFFFFFFu)) ==
        csum_fold(csum_partial(buf.data(), 64, 0xFFFFu)));
  }

  // --- a known answer, so both could not be wrong the same way ------------
  // RFC 1071's worked example: 00 01 f2 03 f4 f5 f6 f7. Its ones-complement
  // sum is 0xddf2, so the checksum on the wire is ~0xddf2 = 0x22 0x0d.
  //
  // Asserted as the two bytes that get stored, not as a uint16_t: the words
  // are summed in memory order, so the value csum_fold() returns is
  // byte-swapped on a little-endian host and not on a big-endian one. What is
  // the same either way is the pair of bytes that lands in the packet, which
  // is also the thing that has to be right.
  {
    const uint8_t ex[] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
    const uint16_t c   = csum_fold(csum_partial(ex, sizeof(ex), 0));
    uint8_t wire[2];
    memcpy(wire, &c, sizeof(c));
    assert(wire[0] == 0x22 && wire[1] == 0x0d);
  }

  // --- alignment, checked without reference to the old implementation -----
  // The differential test above only proves the two agree. If both shared an
  // alignment assumption it would pass anyway, so these two do not consult the
  // oracle at all.

  // 1. Shift invariance. A checksum is a property of a byte sequence, not of
  //    the address it happens to sit at, so the same bytes copied to every
  //    alignment must give the same answer. An unaligned-load bug cannot
  //    survive this.
  {
    const uint8_t pat[] = {0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04,
                           0xa5, 0x5a, 0xff, 0x00, 0x7f, 0x80, 0x12};
    for (size_t len = 1; len <= sizeof(pat); len++) {
      std::vector<uint8_t> at0(len + 16, 0);
      memcpy(at0.data(), pat, len);
      const uint16_t want = csum_fold(csum_partial(at0.data(), len, 0));
      for (size_t off = 1; off < 8; off++) {
        std::vector<uint8_t> shifted(len + 16, 0);
        memcpy(shifted.data() + off, pat, len);
        assert(csum_fold(csum_partial(shifted.data() + off, len, 0)) == want);
      }
    }
  }

  // 2. The RFC 1071 example again, this time starting at an odd address. The
  //    expected bytes come from the RFC, not from this code, so an alignment
  //    fault shared with the old implementation would still show up here.
  {
    const uint8_t ex[] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
    for (size_t off = 0; off < 8; off++) {
      std::vector<uint8_t> buf2(sizeof(ex) + 16, 0xcc);
      memcpy(buf2.data() + off, ex, sizeof(ex));
      const uint16_t c =
          csum_fold(csum_partial(buf2.data() + off, sizeof(ex), 0));
      uint8_t wire[2];
      memcpy(wire, &c, sizeof(c));
      assert(wire[0] == 0x22 && wire[1] == 0x0d);
    }
  }

  // --- a real header checksums to zero when verified ----------------------
  // Summing a header that already carries its checksum must give ~0: this is
  // what a receiver does, so it catches a byte-order slip the oracle shares.
  {
    std::vector<uint8_t> pkt(
        sizeof(struct iphdr) + sizeof(struct tcphdr) + 40, 0);
    auto* iph     = (struct iphdr*) pkt.data();
    iph->version  = 4;
    iph->ihl      = 5;
    iph->protocol = IPPROTO_TCP;
    iph->tot_len  = htons((uint16_t) pkt.size());
    iph->ttl      = 64;
    iph->saddr    = inet_addr("12.1.1.9");
    iph->daddr    = inet_addr("93.184.216.34");
    auto* th      = (struct tcphdr*) (pkt.data() + sizeof(struct iphdr));
    th->source    = htons(443);
    th->dest      = htons(5001);
    th->doff      = 5;
    for (size_t i = sizeof(struct iphdr) + sizeof(struct tcphdr);
         i < pkt.size(); i++)
      pkt[i] = (uint8_t) (rand() & 0xff);

    ip_csum_set(iph);
    assert(csum_fold(csum_partial(iph, (size_t) iph->ihl * 4, 0)) == 0);

    const size_t l4 = pkt.size() - sizeof(struct iphdr);
    tcp_csum_set(iph, l4);
    uint32_t s              = 0;
    s                       = csum_partial(&iph->saddr, 4, s);
    s                       = csum_partial(&iph->daddr, 4, s);
    const uint16_t proto_be = htons(IPPROTO_TCP);
    const uint16_t len_be   = htons((uint16_t) l4);
    s                       = csum_partial(&proto_be, 2, s);
    s                       = csum_partial(&len_be, 2, s);
    s                       = csum_partial(th, l4, s);
    assert(csum_fold(s) == 0);
  }

  printf("test_csum: all checks passed (%zu differential cases)\n", cases);
  return 0;
}
