/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */
// clang-format off
/* Modified by: Franck Messaoudi <franck.messaoudi@eurecom.fr>
 * Date:        2026-03
 * Changes:     Boy Scout cleanup — extracted upf_interface_map and
 *              redirect_interfaces_map from upf_xdp_maps.h into this
 *              dedicated file, paired with interfaces_types.h.
 *              All max_entries = 1 are runtime placeholders.
 */
// clang-format on

/**
 * @file  interfaces_maps.h
 * @brief BPF map definitions for UPF reference-point interface configuration.
 *
 * Provides:
 *   upf_interface_map        -- per-reference-point IP/port/ifname config
 *   redirect_interfaces_map  -- XDP_REDIRECT targets (N3 uplink, N6 downlink)
 *
 * Depends on: interfaces_types.h
 *
 * 3GPP Ref: 3GPP TS 23.501 Table 6.3.3-1 — UPF reference points
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
 * Key:   u32   slot index (UPLINK=0, DOWNLINK=1, N9=2 ...)
 * Value: u32   ifindex of the target Linux network device
 * Size:  MAX_UPF_REDIRECT_INTERFACES (typically 2-3, set at runtime)
 *
 * Slot assignments (from tail_call_dispatch.h):
 *   UPLINK   = 0  -- redirect to N6 interface
 *   DOWNLINK = 1  -- redirect to N3 interface
 *
 * Populated by userspace via bpf_map_update_elem() with the ifindex
 * of each interface obtained from if_nametoindex().
 */
struct {
  __uint(type, BPF_MAP_TYPE_DEVMAP);
  __uint(max_entries, 1); /* Runtime: MAX_UPF_REDIRECT_INTERFACES */
  __type(key, u32);
  __type(value, u32);
} redirect_interfaces_map SEC(".maps");

#endif /* __INTERFACES_MAPS_H__ */