/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef __QER_MAPS_H__
#define __QER_MAPS_H__

#include <linux/bpf.h>
#include "custom_types.h"
#include "sdf_filter.h"

/* ========================================================================== */
/*                       DYNAMIC MAP SIZE CONFIGURATION                       */
/* ========================================================================== */

/**
 * @brief Maximum number of egress interfaces for packet redirection
 *
 * Volatile constant set from userspace. Controls the size of the
 * egress_ifindex DEVMAP used for redirecting packets to different
 * network interfaces.
 *
 * Typical values:
 * - Small deployment: 2-4 interfaces (N3, N6)
 * - Large deployment: 10+ interfaces (multiple N3/N6 with redundancy)
 */
const volatile int MAX_EGRESS_INTERFACES SEC(".rodata");

/* ========================================================================== */
/*                              BPF MAP DEFINITIONS                           */
/* ========================================================================== */

/**
 * @brief Egress interface index map for packet redirection
 *
 * Type: BPF_MAP_TYPE_DEVMAP
 * Key: Interface direction/type (UPLINK=0, DOWNLINK=1)
 * Value: Network interface index (ifindex)
 *
 * Usage:
 * ```c
 * int key = DOWNLINK;
 * int *ifindex = bpf_map_lookup_elem(&egress_ifindex, &key);
 * if (ifindex) {
 *     return bpf_redirect(*ifindex, 0);
 * }
 * ```
 *
 * This map is populated by userspace with the ifindex of the target
 * egress interface (typically the N3 interface for downlink traffic).
 */
struct {
  __uint(type, BPF_MAP_TYPE_DEVMAP);
  __uint(max_entries, 1); /* MAX_EGRESS_INTERFACES */
  __type(key, u32);       /* Interface direction/ID */
  __type(value, u32);     /* Network interface index */
} egress_ifindex SEC(".maps");

#endif  // __QER_MAPS_H__
