/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
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