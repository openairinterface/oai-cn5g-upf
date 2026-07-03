/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_DESTINATION_INTERFACE_H
#define _PFCP_DESTINATION_INTERFACE_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * enum pfcp_dest_interface_value - Destination Interface values
 * @PFCP_DEST_IFACE_ACCESS: Access interface
 * @PFCP_DEST_IFACE_CORE: Core interface
 * @PFCP_DEST_IFACE_SGI_LAN: SGI-LAN/N6-LAN
 * @PFCP_DEST_IFACE_CP_FUNCTION: CP-function
 * @PFCP_DEST_IFACE_LI_FUNCTION: LI-function (lawful intercept)
 */
enum pfcp_dest_interface_value {
  INTERFACE_VALUE_ACCESS         = 0,
  INTERFACE_VALUE_CORE           = 1,
  INTERFACE_VALUE_SGI_LAN_N6_LAN = 2,
  INTERFACE_VALUE_CP_FUNCTION    = 3,
  INTERFACE_VALUE_LI_FUNCTION    = 4
};

/**
 * struct destination_interface - Destination Interface IE
 * @base: Common IE header
 * @interface_value: Destination interface identifier (4 bits)
 * @spare: Spare bits (4 bits)
 */
struct destination_interface {
  // struct ie_base base;
  __u8 spare : 4, interface_value : 4;
} __attribute__((packed));

#endif /* _PFCP_DESTINATION_INTERFACE_H */
