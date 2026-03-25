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
 * Changes:     Boy Scout cleanup — split interfaces.h into
 *              interfaces_types.h (plain-C types, this file) and
 *              interfaces_maps.h (BPF map definitions).
 *              No functional changes to struct or enum content.
 */
// clang-format on

/**
 * @file  interfaces_types.h
 * @brief UPF reference-point type definitions shared between kernel and user.
 *
 * Contains only plain-C types — no BPF map definitions.
 * BPF maps that use these types are in interfaces_maps.h.
 *
 * Used by: all XDP entry programs, xdp_far_apply.c,
 *          session_lookup_eth.c, xdp_n6_eth_entry.c
 *
 * 3GPP Ref: 3GPP TS 23.501 Table 6.3.3-1 — UPF reference points
 */

#ifndef __INTERFACES_TYPES_H__
#define __INTERFACES_TYPES_H__

#include "linux/custom_types.h"

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
struct interface_config {
  u32 ipv4_address;    /**< Interface IPv4 address (network byte order) */
  u32 port;            /**< Port number (PFCP/N4 use; 0 for data-plane) */
  const char* if_name; /**< Linux netdev name (e.g. "eth0", "n3upf0")   */
};

#endif /* __INTERFACES_TYPES_H__ */