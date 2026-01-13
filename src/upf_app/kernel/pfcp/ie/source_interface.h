/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*
 * PFCP Source Interface
 * Reference: 3GPP TS 29.244 Section 8.2.2
 */

#ifndef _PFCP_SOURCE_INTERFACE_H
#define _PFCP_SOURCE_INTERFACE_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * enum pfcp_interface_value - Source/Destination Interface values
 * @PFCP_IFACE_ACCESS: Access interface (from UE)
 * @PFCP_IFACE_CORE: Core interface (from network)
 * @PFCP_IFACE_SGI_LAN: SGI-LAN/N6-LAN interface
 * @PFCP_IFACE_CP_FUNCTION: CP-function interface
 * @PFCP_IFACE_5G_VN_INTERNAL: 5G VN internal interface
 */
enum pfcp_interface_value {
  PFCP_IFACE_ACCESS         = 0,
  PFCP_IFACE_CORE           = 1,
  PFCP_IFACE_SGI_LAN        = 2,
  PFCP_IFACE_CP_FUNCTION    = 3,
  PFCP_IFACE_5G_VN_INTERNAL = 4,
};

/**
 * struct source_interface - Source Interface IE
 * @base: Common IE header
 * @interface_value: Interface identifier (4 bits)
 * @spare: Spare bits (4 bits)
 */
struct source_interface {
  // struct ie_base base;
  __u8 spare : 4, interface_value : 4;
} __attribute__((packed));

#endif /* _PFCP_SOURCE_INTERFACE_H */
