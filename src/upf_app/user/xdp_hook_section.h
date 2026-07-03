/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef XDP_HOOK_SECTION_H_
#define XDP_HOOK_SECTION_H_

#include <string>

class XDPSection {
 public:
  static constexpr const char* Uplink_IP_PDU_SESSION =
      "xdp_n3_entry";  ///< GTP-U uplink for IP PDU Session
  static constexpr const char* Downlink_IP_PDU_SESSION =
      "xdp_n6_entry";  ///< Downlink for IP PDU Session
  static constexpr const char* Uplink_ETH_PDU_SESSION =
      "xdp_n3_eth_entry";  ///< GTP-U uplink for ETH PDU Session
  static constexpr const char* Downlink_ETH_PDU_SESSION =
      "xdp_n6_eth_entry";  ///< Downlink for ETH PDU Session
};

#endif  // XDP_HOOK_SECTION_H_