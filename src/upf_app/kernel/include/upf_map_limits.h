/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef __UPF_RODATA_CONSTANT_H__
#define __UPF_RODATA_CONSTANT_H__

/**
 * @file  upf_map_limits.h
 * @brief Single declaration point for all BPF .rodata runtime size constants.
 *
 * These variables are:
 *   - Placed in the ELF .rodata section by the BPF compiler.
 *   - Read-only from the BPF program side (used for bounds checks).
 *   - Written once by userspace before bpf_object__load() via skeleton->rodata.
 *   - NOT sufficient alone to resize a map — userspace must also call
 *     bpf_map__set_max_entries() before load.
 *
 * Include this file from any BPF map header that references a MAX_* constant.
 * Do NOT redeclare these variables in any other header.
 */

/* --------------------------------------------------------------------------
 * Interface / redirect maps  (interfaces_maps.h, eth_pdu_maps.h)
 * -------------------------------------------------------------------------- */

/** Number of UPF reference-point interfaces (N3, N6, N4, ...).
 *  Typical value: 4.  Set from config: max_upf_interfaces. */
const volatile int MAX_UPF_INTERFACES SEC(".rodata");

/** Number of XDP_REDIRECT egress targets (uplink + downlink).
 *  Typical value: 2.  Set from config: max_upf_redirect_interfaces. */
const volatile int MAX_UPF_REDIRECT_INTERFACES SEC(".rodata");

/* --------------------------------------------------------------------------
 * ARP map  (arp_maps.h)
 * -------------------------------------------------------------------------- */

/** ARP cache size.
 *  Typical value: 256.  Set from config: max_arp_entries. */
const volatile int MAX_ARP_ENTRIES SEC(".rodata");

/* --------------------------------------------------------------------------
 * Session / PDR / pipeline maps  (pipeline_maps.h, tail_call_maps.h,
 *                                  bar_maps.h, mar_maps.h, urr_maps.h)
 * -------------------------------------------------------------------------- */

/** Maximum number of concurrent PDU sessions.
 *  Typical value: 1000.  Set from config: max_pdu_sessions. */
const volatile int MAX_PDU_SESSIONS SEC(".rodata");

/** Maximum PDRs per PDU session (array size in pdrs_per_session_map).
 *  Typical value: 16.  Set from config: max_pdrs_per_session. */
const volatile int MAX_PDRS_PER_PDU_SESSION SEC(".rodata");

/** Maximum PDRs per Ethernet PDU session (array size in
 *  eth_session_pdrs_map, read only by match_pdr_eth_n3() in
 *  xdp_pdr_match_kern.c). */
const volatile int MAX_PDRS_PER_ETH_PDU_SESSION SEC(".rodata");

/* --------------------------------------------------------------------------
 * SDF filter map  (sdf_maps.h, pipeline_maps.h)
 * -------------------------------------------------------------------------- */

/** Maximum SDF filters per PDU session.
 *  Typical value: 16.  Set from config: max_sdf_filters_per_session. */
const volatile int MAX_SDF_FILTERS_PER_PDU_SESSION SEC(".rodata");

/* --------------------------------------------------------------------------
 * QoS  (pipeline_maps.h, qer_apply, urr_apply)
 * -------------------------------------------------------------------------- */

/** Maximum number of QoS-enabled sessions (session_qos_enabled_map size).
 *  Equivalent to MAX_PDU_SESSIONS.  Set from config: max_pdu_sessions. */
const volatile int MAX_QOS_ENABLING SEC(".rodata");

/* Reserved for future use — per-UE equipment tracking.
 * Uncomment and set from config when multi-UE-per-session is required. */
// const volatile int MAX_USER_EQUIPMENTS SEC(".rodata");

#endif /* __UPF_RODATA_CONSTANT_H__ */
