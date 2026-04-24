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
 * Changes:     Boy Scout cleanup — extracted sdf_filters_map from
 *              upf_xdp_maps.h into this dedicated file, paired with
 *              sdf_types.h.  max_entries = 1 is a runtime placeholder.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 §8.2.5 — SDF Filter IE
 */
// clang-format on

/**
 * @file  sdf_maps.h
 * @brief BPF map definition for SDF filter rules.
 *
 * Provides:
 *   sdf_filters_map  -- global SDF filter rules across all sessions
 *
 * Depends on: sdf_types.h
 *
 * Size = MAX_PDU_SESSIONS x MAX_SDF_FILTERS_PER_PDU_SESSION (set at runtime).
 * This is a GLOBAL map — do not size it per-session.
 *
 * 3GPP Ref: 3GPP TS 29.244 V17.10.0 §8.2.5 — SDF Filter IE
 */

#ifndef __SDF_MAPS_H__
#define __SDF_MAPS_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "sdf_types.h"
#include "upf_map_limits.h"

/* ==========================================================================
 * sdf_filters_map
 * ========================================================================== */

/**
 * @brief Global SDF filter rule table.
 *
 * Key:   struct session_qfi   {seid, qfi}
 * Value: struct sdf_filtr     {protocol, src_addr, src_port,
 *                              dst_addr, dst_port, session}
 * Size:  MAX_PDU_SESSIONS x MAX_SDF_FILTERS_PER_PDU_SESSION
 *
 * Written by control plane during PFCP Session Establishment (§7.5.2)
 * from the SDF Filter IE (§8.2.5).
 * Read by pdr_match.c and xdp_qer_apply.c to classify packets into
 * QoS flows.
 *
 * NOTE: Total size = sessions x filters_per_session.
 *       Do NOT set max_entries = max_sdf_filters_per_pdu_session alone.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(
      max_entries,
      1); /* Runtime: MAX_PDU_SESSIONS x MAX_SDF_FILTERS_PER_PDU_SESSION */
  __type(key, struct session_qfi);
  __type(value, struct sdf_filtr);
} sdf_filters_map SEC(".maps");

#endif /* __SDF_MAPS_H__ */