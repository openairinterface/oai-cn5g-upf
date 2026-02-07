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

/*
 * @file upf_xdp_maps.h
 * @brief BPF map definitions for UPF XDP data path
 *
 * =============================================================================
 * MAP SIZING GUIDE
 * =============================================================================
 *
 * CONFIGURATION VARIABLES (from YAML):
 *   max_pdu_sessions                    - Total number of PDU sessions
 *   max_pdrs_per_pdu_session            - PDR limit per session
 *   max_sdf_filters_per_pdu_session     - SDF filter limit per session
 *   max_arp_entries                     - ARP cache size
 *   max_upf_interfaces                  - UPF reference points
 *
 * MAP SIZE FORMULAS:
 *
 *   SESSION-SCOPED maps (one entry per session):
 *     size = max_pdu_sessions
 *
 *   GLOBAL/RULE maps (entries across all sessions):
 *     size = max_pdu_sessions × max_*_per_pdu_session
 *
 * IMPORTANT: All max_entries=1 here are PLACEHOLDERS.
 * Actual sizes are set at runtime by ConfigurePfcpSessionLookupMaps().
 * =============================================================================
 */

#ifndef __PFCP_SESSION_LOOKUP_MAPS_H__
#define __PFCP_SESSION_LOOKUP_MAPS_H__

#include "linux/custom_types.h"
#include "ie/group_ie/create_pdr.h"
#include "ie/teid.h"
#include "pfcp/pfcp_pdr.h"
#include "pfcp/pfcp_far.h"
#include "arp_table.h"
#include "rules_matching_pdr.h"
#include "interfaces.h"
#include "session_id.h"
#include "upf_xdp_limits.h"
#include <linux/bpf.h>
#include <stdint.h>

/*
 * =============================================================================
 * .rodata CONSTANTS - Set by userspace before BPF load
 * =============================================================================
 */
const volatile int MAX_UPF_INTERFACES SEC(".rodata");
const volatile int MAX_UPF_REDIRECT_INTERFACES SEC(".rodata");
const volatile int MAX_PDU_SESSIONS SEC(".rodata");
const volatile int MAX_PDRS_PER_PDU_SESSION SEC(".rodata");
const volatile int MAX_SDF_FILTERS_PER_PDU_SESSION SEC(".rodata");
const volatile int MAX_ARP_ENTRIES SEC(".rodata");
const volatile int MAX_QOS_ENABLING SEC(".rodata");

/*
 * =============================================================================
 * INTERFACE MAPS (fixed size)
 * =============================================================================
 */

/**
 * upf_interface_map - UPF reference point configuration
 * Size: MAX_UPF_INTERFACES (typically 4)
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_UPF_INTERFACES */
  __type(key, reference_point_t);
  __type(value, struct interface_config);
} upf_interface_map SEC(".maps");

/**
 * redirect_interfaces_map - XDP_REDIRECT targets
 * Size: MAX_UPF_REDIRECT_INTERFACES (typically 2)
 */
struct {
  __uint(type, BPF_MAP_TYPE_DEVMAP);
  __uint(max_entries, 1); /* Runtime: MAX_UPF_REDIRECT_INTERFACES */
  __type(key, u32);       // id
  __type(value, u32);     // tx port
} redirect_interfaces_map SEC(".maps");

/*
 * =============================================================================
 * SESSION-SCOPED MAPS
 * Size = max_pdu_sessions (one entry per session)
 * =============================================================================
 */
/**
 * session_by_ue_ip_map - UE IP to session lookup
 * Size: MAX_PDU_SESSIONS
 * Key: UE IPv4 address
 * Value: session_id {seid, teid_ul, teid_dl}
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_PDU_SESSIONS */
  __type(key, u32);
  __type(value, struct session_id);
} session_by_ue_ip_map SEC(".maps");

/**
 * session_pdrs_map - PDR array per session
 * Size: MAX_PDU_SESSIONS (one entry per session, value is array)
 * Key: SEID
 * Value: Array of PDRs for this session
 *
 * NOTE: Each entry contains array[MAX_PDRS_PER_PDU_SESSION_LIMIT].
 * Map size = number of sessions, NOT number of PDRs!
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_PDU_SESSIONS */
  __type(key, u64);
  __type(value, struct pfcp_pdr[MAX_PDRS_PER_PDU_SESSION_LIMIT]);
} pdrs_per_session_map SEC(".maps");

/**
 * session_qos_enabled_map - QoS enable flag per session
 * Size: MAX_PDU_SESSIONS
 * Key: SEID
 * Value: 0=disabled, 1=enabled
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_PDU_SESSIONS */
  __type(key, u64);
  __type(value, u32);
} session_qos_enabled_map SEC(".maps");

/*
 * =============================================================================
 * GLOBAL RULE MAPS
 * Size = max_pdu_sessions × max_*_per_pdu_session
 * =============================================================================
 * These maps store individual rules/filters across ALL sessions.
 */

/**
 * rules_match_pdr_map - PDR to FAR/QER association
 * Size: MAX_PDU_SESSIONS × MAX_PDRS_PER_PDU_SESSION
 * Key: {pdr_id, seid}
 * Value: {FAR, QER references}  <TO BE EXTENDED>
 *
 * Example: 1000 sessions × 16 PDRs = 16,000 entries
 */

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(
      max_entries,
      1); /* Runtime: MAX_PDU_SESSIONS × MAX_PDRS_PER_PDU_SESSION */
  __type(key, struct pdrs_per_session);
  __type(value, struct rules_match_pdr);  // < FAR, QER, /* MAR, BAR, URR */ >
} rules_match_pdr_map SEC(".maps");

/**
 * sdf_filters_map - SDF filter definitions (GLOBAL)
 * Size: MAX_PDU_SESSIONS × MAX_SDF_FILTERS_PER_PDU_SESSION
 * Key: {qfi, seid}
 * Value: SDF filter definition
 *
 * CRITICAL: This is a GLOBAL map for ALL sessions!
 * Total size = sessions × filters_per_session
 * Example: 1000 sessions × 16 filters = 16,000 entries
 *
 * Do NOT set size = max_sdf_filters_per_pdu_session (that's per-session limit!)
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(
      max_entries,
      1); /* Runtime: MAX_PDU_SESSIONS × MAX_SDF_FILTERS_PER_PDU_SESSION */
  __type(key, struct session_qfi);  // <qfi, seid>
  __type(value, struct sdf_filtr);
} sdf_filters_map SEC(".maps");

/*
 * =============================================================================
 * NETWORK MAPS
 * =============================================================================
 */

/**
 * arp_table_map - ARP cache for next-hop resolution
 * Size: MAX_ARP_ENTRIES
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);           /* Runtime: MAX_ARP_ENTRIES */
  __type(key, u32);                 // IPv4 address
  __type(value, struct arp_entry);  // <IP Address, MAC address>
} arp_table_map SEC(".maps");

/*
 * =============================================================================
 * FRAMED ROUTING MAPS
 * =============================================================================
 */

/**
 * m_framed_route_mapping - Framed route to UE IP
 * Size: MAX_PDU_SESSIONS
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* Runtime: MAX_PDU_SESSIONS */
  __type(key, u32);       // hash_framed_routing_key
  __type(value, u32);     // ue_ip
} m_framed_route_mapping SEC(".maps");

/**
 * framed_routing_flag - Global enable flag
 * Size: 1
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);  // Single entry for the flag
  __type(key, u8);         // Key is a constant, e.g., 0
  __type(value, u8);       // Value indicates if framed routing is enabled
} framed_routing_flag SEC(".maps");

#endif  // __PFCP_SESSION_LOOKUP_MAPS_H__
