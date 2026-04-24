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
/* Author: Franck Messaoudi <franck.messaoudi@eurecom.fr>
 * Date:   2026-04
 * Purpose: Single source of truth for all BPF .rodata size constants.
 *
 * Problem solved:
 *   Before this file, every map header (interfaces_maps.h, pipeline_maps.h,
 *   eth_pdu_maps.h, arp_maps.h, ...) redeclared the same
 *   `const volatile int MAX_* SEC(".rodata")` variables independently.
 *   Any kernel program including more than one of those headers got duplicate
 *   symbol errors or — worse — multiple independent rodata variables that
 *   each had to be set separately by userspace.
 *
 * Solution:
 *   All `const volatile int MAX_*` declarations live here ONLY.
 *   Every map header that needs a size constant includes this file instead
 *   of re-declaring it. The include guard prevents duplicate declarations
 *   within a single compilation unit.
 *
 * Userspace counterpart:
 *   Each variable here is set before bpf_object__load() via:
 *     skel->rodata->MAX_XXX = upf::GetMaxXxx();
 *   and the map is resized via:
 *     bpf_map__set_max_entries(skel->maps.xxx_map, upf::GetMaxXxx());
 *   See FARProgram::ConfigureMaps() for the canonical pattern.
 */
// clang-format on

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
