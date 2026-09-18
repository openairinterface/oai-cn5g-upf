/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 *
 * Self-check for the GTP-U header walk. Header-only:
 *
 *   g++ -std=c++17 -O2 src/upf_app/simpleswitch/test_gtpu_walk.cpp \
 *       -o /tmp/test_gtpu_walk && /tmp/test_gtpu_walk
 *
 * This walk has been wrong twice, in both directions, and each time the only
 * symptom was that uplink traffic stopped. Every shape a gNB is known to send
 * -- and a few it should not -- is pinned here.
 */

#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

#include "gtpu_walk.hpp"

using oai::upf::gtpu_inner;

namespace {

/// Build a G-PDU: 8 mandatory bytes, the optional block when any of E/S/PN is
/// set, then `exts` extension headers of one 4-byte unit each.
std::vector<uint8_t> gpdu(uint8_t flags, int exts, std::size_t payload) {
  std::vector<uint8_t> p;
  p.push_back(0x30 | flags);  // version 1, PT 1, then E/S/PN
  p.push_back(0xff);          // G-PDU
  p.push_back(0);
  p.push_back(0);  // length, filled by the caller's own arithmetic
  for (int i = 0; i < 4; i++) p.push_back(0);  // TEID
  if (flags & 0x07) {
    p.push_back(0);
    p.push_back(0);                    // sequence number
    p.push_back(0);                    // N-PDU number
    p.push_back(exts > 0 ? 0x85 : 0);  // next extension type
    for (int e = 0; e < exts; e++) {
      p.push_back(1);  // length, in 4-byte units
      p.push_back(0);
      p.push_back(0);                        // content
      p.push_back(e + 1 < exts ? 0x85 : 0);  // next, 0 ends the chain
    }
  }
  const std::size_t hdr = p.size();
  for (std::size_t i = 0; i < payload; i++) p.push_back(0x45);
  const uint16_t len = (uint16_t) (p.size() - 8);
  p[2]               = (uint8_t) (len >> 8);
  p[3]               = (uint8_t) (len & 0xff);
  (void) hdr;
  return p;
}

void expect(
    const char* what, const std::vector<uint8_t>& p, bool ok,
    std::size_t want_off, std::size_t want_len) {
  std::size_t off = 0, len = 0;
  const bool got = gtpu_inner(p.data(), p.size(), off, len);
  printf(
      "  %-42s %s off=%zu len=%zu\n", what, got ? "forward" : "DROP   ", off,
      len);
  assert(got == ok && "wrong verdict");
  if (ok) {
    assert(off == want_off && "inner packet starts in the wrong place");
    assert(len == want_len && "inner packet is the wrong length");
  }
}

}  // namespace

int main() {
  // What the flags actually mean: one 4-byte block if any of E/S/PN is set,
  // and extension headers only for E.
  expect("no optional fields", gpdu(0x00, 0, 100), true, 8, 100);
  expect("S only (sequence number)", gpdu(0x02, 0, 100), true, 12, 100);
  expect("PN only", gpdu(0x01, 0, 100), true, 12, 100);
  expect("E, one extension (PDU session)", gpdu(0x04, 1, 100), true, 16, 100);
  expect("E and S", gpdu(0x06, 1, 100), true, 16, 100);
  expect("E, two chained extensions", gpdu(0x04, 2, 100), true, 20, 100);
  expect("E set, chain empty", gpdu(0x04, 0, 100), true, 12, 100);

  // A sender whose length field disagrees with the datagram keeps its
  // traffic: the wire says where the packet ends.
  {
    std::vector<uint8_t> p = gpdu(0x04, 1, 100);
    p[2]                   = 0xff;
    p[3]                   = 0xff;  // claims 65535 bytes, sent 116
    expect("claims far more than it sent", p, true, 16, 100);
    p[2] = 0;
    p[3] = 4;  // claims 4 bytes, sent 108 after the header
    expect("claims far less than it sent", p, true, 16, 100);
  }

  // Nothing to forward, and nothing to read past either.
  expect("header only, no payload", gpdu(0x04, 1, 0), false, 0, 0);
  expect("shorter than a header", std::vector<uint8_t>(4, 0), false, 0, 0);
  {
    std::vector<uint8_t> p = gpdu(0x04, 1, 100);
    p[12]                  = 0;  // extension length 0: the walk cannot advance
    expect("extension header of zero length", p, false, 0, 0);
    p     = gpdu(0x04, 1, 100);
    p[12] = 0xff;  // a chain longer than the datagram
    expect("extension chain past the datagram", p, false, 0, 0);
  }
  printf("gtpu_walk: ok\n");
  return 0;
}
