/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 *
 * Self-check for GSO type normalisation. Header-only:
 *
 *   g++ -std=c++17 -O2 src/upf_app/simpleswitch/test_vnet_gso.cpp \
 *       -o /tmp/test_vnet_gso && /tmp/test_vnet_gso
 *
 * gso_type is a type OR-ed with flags, and TUN_F_TSO_ECN is advertised, so an
 * ECN-marked TCPv4 super-packet arrives as 0x81. Comparing it for equality
 * against GSO_TCPV4 calls it unsplittable; segment_and_forward() then forwards
 * it whole, where -- being a super-packet -- it does not fit a slot and is
 * dropped. That looks like heavy downlink loss on exactly the senders that
 * negotiate ECN.
 */

#include <cassert>
#include <cstdio>

#include "vnet_hdr.hpp"

using oai::upf::app::vnet_gso_base;

int main() {
  // The regression: with and without ECN must normalise to the same type, so
  // both take the segmentation path in segment_and_forward().
  assert(vnet_gso_base(UPF_VNET_HDR_GSO_TCPV4) == UPF_VNET_HDR_GSO_TCPV4);
  assert(
      vnet_gso_base(UPF_VNET_HDR_GSO_TCPV4 | UPF_VNET_HDR_GSO_ECN) ==
      UPF_VNET_HDR_GSO_TCPV4);

  // The same holds for the types that are forwarded whole rather than split:
  // ECN must not turn one of them into something else either.
  assert(vnet_gso_base(UPF_VNET_HDR_GSO_NONE) == UPF_VNET_HDR_GSO_NONE);
  assert(
      vnet_gso_base(UPF_VNET_HDR_GSO_NONE | UPF_VNET_HDR_GSO_ECN) ==
      UPF_VNET_HDR_GSO_NONE);
  assert(
      vnet_gso_base(UPF_VNET_HDR_GSO_TCPV6 | UPF_VNET_HDR_GSO_ECN) ==
      UPF_VNET_HDR_GSO_TCPV6);

  // Only ECN is cleared. An unrecognised flag has to survive, so that the
  // comparison in segment_and_forward() fails and the packet is forwarded
  // whole -- never segmented as a TCPv4 packet it is not.
  constexpr uint8_t unknown = 0x40;
  assert(
      vnet_gso_base(UPF_VNET_HDR_GSO_TCPV4 | unknown) !=
      UPF_VNET_HDR_GSO_TCPV4);
  assert(
      vnet_gso_base(UPF_VNET_HDR_GSO_TCPV4 | unknown | UPF_VNET_HDR_GSO_ECN) !=
      UPF_VNET_HDR_GSO_TCPV4);

  printf("test_vnet_gso: all checks passed\n");
  return 0;
}
