/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef XSK_FRAME_HPP_SEEN
#define XSK_FRAME_HPP_SEEN

#include <cstddef>
#include <cstdint>

namespace oai::upf {

/// The IPv4 packet inside an AF_XDP frame; empty (data == nullptr) when the
/// frame must be dropped.
struct xsk_ipv4 {
  const uint8_t* data = nullptr;
  size_t len          = 0;
  explicit operator bool() const { return data != nullptr; }
};

/// Ethernet II header length. 802.1Q frames never reach BAR (parse_eth hands
/// them to the kernel), so there is exactly one header to strip.
constexpr size_t XSK_ETH_HLEN = 14;
/// Smallest frame that can hold an Ethernet header and an IPv4 header.
constexpr size_t XSK_MIN_FRAME = XSK_ETH_HLEN + 20;

/**
 * @brief Find the IPv4 packet in a frame the XDP BAR program redirected to an
 *        AF_XDP socket (DL buffering on the eBPF datapath).
 *
 * The frame is Ethernet + IPv4, as received on N6. The replay expects the
 * IPv4 header at byte 0, so the Ethernet header is stripped.
 *
 * The frame comes from the data network and XDP did not check the IPv4
 * lengths. The lookup trusts them, so a bad Total Length would read past the
 * buffer: check it here. The span ends at Total Length, which also drops
 * Ethernet padding.
 *
 * Checks: len >= 34; EtherType IPv4 (0x0800); version 4; IHL >= 5;
 * IHL * 4 <= Total Length <= len - 14. No allocation, no logging.
 */
inline xsk_ipv4 xsk_ipv4_span(const uint8_t* frame, size_t len) {
  if (!frame || len < XSK_MIN_FRAME) return {};
  const uint16_t h_proto = (uint16_t) ((frame[12] << 8) | frame[13]);
  if (h_proto != 0x0800) return {};
  const uint8_t* ip   = frame + XSK_ETH_HLEN;
  const size_t ip_max = len - XSK_ETH_HLEN;
  if ((ip[0] >> 4) != 4) return {};
  const size_t ihl_bytes = (size_t) (ip[0] & 0x0f) * 4;
  if (ihl_bytes < 20) return {};
  const size_t tot_len = (size_t) ((ip[2] << 8) | ip[3]);
  if (tot_len < ihl_bytes || tot_len > ip_max) return {};
  return {ip, tot_len};
}

}  // namespace oai::upf

#endif  // XSK_FRAME_HPP_SEEN
