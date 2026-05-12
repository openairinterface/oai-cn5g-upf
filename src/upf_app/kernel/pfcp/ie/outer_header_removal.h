/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_OUTER_HEADER_REMOVAL_H
#define _PFCP_OUTER_HEADER_REMOVAL_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * enum pfcp_ohr_desc - Outer Header Removal description values
 * @PFCP_OHR_GTP_U_UDP_IPV4: Remove GTP-U/UDP/IPv4
 * @PFCP_OHR_GTP_U_UDP_IPV6: Remove GTP-U/UDP/IPv6
 * @PFCP_OHR_UDP_IPV4: Remove UDP/IPv4
 * @PFCP_OHR_UDP_IPV6: Remove UDP/IPv6
 * @PFCP_OHR_IPV4: Remove IPv4
 * @PFCP_OHR_IPV6: Remove IPv6
 * @PFCP_OHR_GTP_U_UDP_IP: Remove GTP-U/UDP/IP
 * @PFCP_OHR_VLAN_STAG: Remove VLAN S-TAG
 * @PFCP_OHR_STAG_CTAG: Remove S-TAG and C-TAG
 */
enum pfcp_ohr_desc {
  PFCP_OHR_GTP_U_UDP_IPV4 = 0,
  PFCP_OHR_GTP_U_UDP_IPV6 = 1,
  PFCP_OHR_UDP_IPV4       = 2,
  PFCP_OHR_UDP_IPV6       = 3,
  PFCP_OHR_IPV4           = 4,
  PFCP_OHR_IPV6           = 5,
  PFCP_OHR_GTP_U_UDP_IP   = 6,
  PFCP_OHR_VLAN_STAG      = 7,
  PFCP_OHR_STAG_CTAG      = 8,
};

/**
 * struct outer_header_removal - Outer Header Removal IE
 * @base: Common IE header
 * @description: Outer header removal description
 * @gtpu_ext_hdr_deletion: GTP-U extension header deletion flags
 *
 * Specifies which outer header(s) to remove from packets.
 *
 * gtpu_ext_hdr_deletion bit 0: PDU Session Container
 */
struct outer_header_removal {
  // struct ie_base base;
  __u8 description;
  __u8 gtpu_ext_hdr_deletion;
} __attribute__((packed));

#endif /* _PFCP_OUTER_HEADER_REMOVAL_H */
