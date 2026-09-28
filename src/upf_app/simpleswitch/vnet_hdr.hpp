/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_VNET_HDR_HPP_SEEN
#define FILE_VNET_HDR_HPP_SEEN

#include <cstddef>
#include <cstdint>

namespace oai::upf::app {

/**
 * @brief The virtio-net header a tun queue opened with IFF_VNET_HDR prefixes
 *        to every packet, in both directions.
 *
 * Declared here rather than included from <linux/virtio_net.h>, which does not
 * compile as C++: it declares a field called `class`. The layout is fixed by
 * the virtio specification and is what TUNSETVNETHDRSZ is told to expect, so
 * restating it is safe -- but the size must stay 10 bytes, hence the assert.
 *
 * In its own header so that vnet_gso_base() below can be tested without
 * building the switch; see test_vnet_gso.cpp.
 */
struct upf_vnet_hdr {
  uint8_t flags;
  uint8_t gso_type;
  uint16_t hdr_len;     ///< bytes of header before the payload
  uint16_t gso_size;    ///< MSS: payload bytes per segment once split
  uint16_t csum_start;  ///< only meaningful with NEEDS_CSUM
  uint16_t csum_offset;
} __attribute__((packed));
static_assert(
    sizeof(struct upf_vnet_hdr) == 10,
    "virtio_net_hdr is 10 bytes; TUNSETVNETHDRSZ agrees that with the kernel");

/// @name virtio_net_hdr values used here (virtio spec §5.1.6).
/// @{
#define UPF_VNET_HDR_F_NEEDS_CSUM 1
#define UPF_VNET_HDR_GSO_NONE 0
#define UPF_VNET_HDR_GSO_TCPV4 1
#define UPF_VNET_HDR_GSO_TCPV6 4
/// A flag OR-ed into gso_type, not a type of its own. TUN_F_TSO_ECN is
/// advertised, so the kernel sets it on a GSO packet whose segments carry
/// ECN -- and gso_type then reads 0x81, not 0x01.
#define UPF_VNET_HDR_GSO_ECN 0x80
/// @}

/**
 * @brief The GSO type with the ECN flag taken off.
 *
 * gso_type is a type OR-ed with flags, so it has to be normalised before it is
 * compared with GSO_TCPV4 or GSO_TCPV6. An ECN-marked TCPv4 super-packet
 * arrives as 0x81, and an equality test against 0x01 calls it unsplittable --
 * it is then forwarded whole, does not fit a slot, and is dropped. That costs
 * ECN-negotiating senders (DCTCP, L4S) their downlink.
 *
 * Only the ECN bit is cleared. Any other flag stays set and so fails the
 * comparison, which leaves an unrecognised GSO type forwarded whole rather
 * than segmented as something it is not.
 */
inline uint8_t vnet_gso_base(const uint8_t gso_type) {
  return (uint8_t) (gso_type & (uint8_t) ~UPF_VNET_HDR_GSO_ECN);
}

}  // namespace oai::upf::app

#endif /* FILE_VNET_HDR_HPP_SEEN */
