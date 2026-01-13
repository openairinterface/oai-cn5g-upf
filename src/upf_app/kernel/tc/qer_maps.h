/**
 * @file qer_maps.h
 * @brief QER (QoS Enforcement Rules) TC datapath map definitions
 *
 * This header defines BPF maps used by the QER TC (Traffic Control) programs
 * for QoS enforcement in the 5G UPF datapath. These maps enable:
 *
 * - Egress interface configuration for packet redirection
 * - QER rules storage per session and QFI
 * - QoS flow classification and rate limiting parameters
 * - Traffic statistics tracking per QoS flow
 *
 * Map Size Configuration:
 * All maps use dynamic sizing through volatile constants that are set from
 * userspace during BPF program loading. This allows flexible configuration
 * based on deployment requirements.
 *
 * Architecture:
 * ```
 * XDP (upf_xdp_kern) → [metadata: seid, qfi] → TC Egress (qer_tc_kernel)
 *                                                      ↓
 *                                               [QoS Classification]
 *                                                      ↓
 *                                               TC Ingress (redirect)
 *                                                      ↓
 *                                               N3 Interface
 * ```
 *
 * @see 3GPP TS 23.501 - QoS Framework
 * @see 3GPP TS 29.244 - PFCP QER IE
 *
 * @copyright 2024 OpenAirInterface
 * @license GPL-2.0
 */

#ifndef __QER_MAPS_H__
#define __QER_MAPS_H__

#include <linux/bpf.h>
#include "linux/custom_types.h"
#include "sdf_filter.h"

/* ========================================================================== */
/*                       DYNAMIC MAP SIZE CONFIGURATION                       */
/* ========================================================================== */

/**
 * @brief Maximum number of egress interfaces for packet redirection
 *
 * Volatile constant set from userspace. Controls the size of the
 * m_egress_ifindex DEVMAP used for redirecting packets to different
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
 * int *ifindex = bpf_map_lookup_elem(&m_egress_ifindex, &key);
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
} m_egress_ifindex SEC(".maps");

#endif  // __QER_MAPS_H__
