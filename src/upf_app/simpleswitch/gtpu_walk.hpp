/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef GTPU_WALK_HPP_SEEN
#define GTPU_WALK_HPP_SEEN

#include <cstddef>
#include <cstdint>

namespace oai::upf {

/**
 * @brief Find the user packet inside a GTP-U G-PDU (3GPP TS 29.281 §5.1).
 *
 * The header is 8 mandatory bytes, then -- if any of E, S or PN is set -- ONE
 * 4-byte block holding the Sequence Number, the N-PDU Number and the type of
 * the first extension header. Extensions follow only when E is set, chained,
 * each 4 * its first byte long, the last byte of each naming the next.
 *
 * The end of the user packet is the end of the datagram, not the length the
 * sender claims. A UDP datagram's length is exact and GTP-U has no padding, so
 * the wire already says where the packet stops; a sender that counts its own
 * header differently -- and they do -- should not have its user's traffic
 * dropped over an arithmetic disagreement. Trailing bytes, if any sender ever
 * sends them, cost nothing: the IP stack trims to the inner header's own
 * length. The claim is worth a warning, never a drop.
 *
 * Every read is bounded by `len`, so a header that says more than arrived
 * cannot walk this off the end of the buffer either.
 *
 * @param buf        the UDP payload, starting at the GTP-U header
 * @param len        how many bytes of it were received
 * @param off        out: where the user packet starts
 * @param inner_len  out: how long it is
 * @returns false only when there is genuinely nothing to forward: too short to
 *          hold a header, or a header that consumes the whole datagram.
 */
inline bool gtpu_inner(
    const uint8_t* buf, std::size_t len, std::size_t& off,
    std::size_t& inner_len) {
  constexpr std::size_t HDR = 8;
  constexpr uint8_t E = 0x04, S = 0x02, PN = 0x01;
  if (len < HDR) return false;

  const uint8_t flags = buf[0];
  off                 = HDR;
  if (flags & (E | S | PN)) {
    off += 4;
    if (off > len) return false;
    // buf[off - 1] is the type of the next extension header; 0 ends the chain.
    while ((flags & E) && off < len && buf[off - 1]) {
      const uint8_t units = buf[off];
      if (units == 0) return false;  // malformed: the walk would not advance
      off += (std::size_t) units * 4;
      if (off > len) return false;  // the chain runs past what arrived
    }
  }
  if (off >= len) return false;
  inner_len = len - off;
  return true;
}

}  // namespace oai::upf

#endif /* GTPU_WALK_HPP_SEEN */
