/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef __INTERFACES_MAPS_H__
#define __INTERFACES_MAPS_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "interfaces_types.h"
#include "upf_map_limits.h"

/* ==========================================================================
 * upf_interface_map
 * ========================================================================== */

/**
 * @brief UPF reference-point interface configuration.
 *
 * Key:   reference_point_t        N3_INTERFACE / N6_INTERFACE / ...
 * Value: struct interface_config  {ipv4_address, port, if_name}
 * Size:  MAX_UPF_INTERFACES (typically 4-5, set at runtime)
 *
 * Written once by userspace before BPF program load.
 * Read-only by all XDP programs in the hot path.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_UPF_INTERFACES */
  __type(key, reference_point_t);
  __type(value, struct interface_config);
} upf_interface_map SEC(".maps");

/* ==========================================================================
 * redirect_interfaces_map
 * ========================================================================== */

/**
 * @brief XDP_REDIRECT target interface index map.
 *
 * Key:   u32   slot index (FlowDirection enum, see linux/custom_types.h)
 * Value: u32   ifindex of the target Linux network device
 * Size:  MAX_UPF_REDIRECT_INTERFACES (typically 2-3, set at runtime)
 *
 * Slot assignments (FlowDirection enum, kernel/include/linux/custom_types.h):
 *   DOWNLINK = 0  -- redirect to N3 interface (gNB-facing, GTP-U encapped)
 *   UPLINK   = 1  -- redirect to N6 interface (DN-facing, after decap)
 *
 * Populated by userspace via bpf_map_update_elem() with the ifindex
 * of each interface obtained from if_nametoindex():
 *   - IP-PDU path:  UPF_XDPProgram::Setup() (upf_xdp_user.cpp)
 *   - ETH-PDU path: N6EthEntryProgram::Setup() (n6_eth_entry_user.cpp)
 */
struct {
  __uint(type, BPF_MAP_TYPE_DEVMAP);
  __uint(max_entries, 1); /* Runtime: MAX_UPF_REDIRECT_INTERFACES */
  __type(key, u32);
  __type(value, u32);
} redirect_interfaces_map SEC(".maps");

#endif /* __INTERFACES_MAPS_H__ */