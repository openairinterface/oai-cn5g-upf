/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef __INTERFACES_TYPES_H__
#define __INTERFACES_TYPES_H__

#include "custom_types.h"

/* ==========================================================================
 * UPF reference point identifier
 * ========================================================================== */

/**
 * @brief 5G UPF reference point identifiers.
 *
 * Used as the map key in upf_interface_map to retrieve per-interface
 * configuration. Values correspond to:
 *   N3  — RAN <-> UPF (GTP-U user plane)
 *   N6  — UPF <-> Data Network
 *   N4  — SMF <-> UPF (PFCP control plane)
 *   N9  — UPF <-> UPF (inter-UPF tunnel)
 *   N19 — PSA-UPF <-> UL-CL/BP (ULCL architecture)
 */
typedef enum {
  N3_INTERFACE  = 0,
  N6_INTERFACE  = 1,
  N4_INTERFACE  = 2,
  N9_INTERFACE  = 3,
  N19_INTERFACE = 4,
} reference_point_t;

/* ==========================================================================
 * Interface configuration
 * ========================================================================== */

/**
 * @brief Per-interface configuration stored in upf_interface_map.
 *
 * Populated by userspace (SessionProgramManager) before BPF program load.
 */

#define IF_NAME_MAX_LEN 16 /* IFNAMSIZ = 16, fits all Linux interface names */

struct interface_config {
  u32 ipv4_address;              /**< IPv4 address (network byte order)       */
  u32 port;                      /**< Port (PFCP/N4); 0 for data-plane ifaces */
  char if_name[IF_NAME_MAX_LEN]; /**< Linux netdev name, NUL-terminated       */
};

#endif /* __INTERFACES_TYPES_H__ */