/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef UPF_PIPELINE_CONFIG_H_
#define UPF_PIPELINE_CONFIG_H_

#include <cstdint>

// ==========================================================================
// PDU Session Type
// ==========================================================================

/**
 * @brief PDU session type — controls which XDP entry programs are attached
 *
 * Derived from upf_cfg.enable_eth_pdu (bool) in
 * Configuration::BuildNetworkConfig(): enable_eth_pdu == false  →  IP (default)
 *   enable_eth_pdu == true   →  Ethernet
 *
 * IP:       upf_n3_entry / upf_n6_entry attached to N3/N6
 * Ethernet: upf_n3_eth_entry / upf_n6_eth_entry attached to N3/N6
 *
 * @see 3GPP TS 23.501 Section 5.6.10 — PDU Session Types
 */
enum class PduSessionType : uint8_t {
  IP       = 0,  ///< IP PDU Session (IPv4/IPv6 inner packet)
  Ethernet = 1   ///< Ethernet PDU Session (IEEE 802.3 inner frame)
};

// ==========================================================================
// Pipeline Feature Flags
// ==========================================================================

/**
 * @brief Feature flags controlling which programs are loaded into PROG_ARRAY
 *
 * Built by UserPlaneComponent::BuildFeatureFlags() from upf::g_net_cfg and
 * passed to UPF_XDPProgram::Setup() → PopulateProgramArray().
 *
 * Each flag maps to one optional PROG_ARRAY slot in feature_dispatch_map.
 * An empty slot is a safe no-op in the kernel tail-call chain.
 *
 * @see kernel/include/tail_call_types.h -- enum upf_prog_index for slot
 * assignments
 * @see kernel/xdp/tail_call_dispatch.h — kernel-side enum (must stay in sync)
 */
struct PipelineFeatureFlags {
  bool enable_qer = false;  ///< PROG_QER  — QoS gate + MBR/GBR enforcement
  bool enable_urr = false;  ///< PROG_URR  — volume/time usage reporting
  bool enable_bar = false;  ///< PROG_BAR  — DL buffering + DDN notification
  bool enable_mar = false;  ///< PROG_MAR  — ATSSS multi-access steering
  bool enable_framed_routing = false;  ///< PROG_FRAMED_ROUTING — per-UE routes
  PduSessionType pdu_type    = PduSessionType::IP;  ///< Entry program set
};

// ==========================================================================
// PROG_ARRAY Slot Indices
// ==========================================================================
/*
 * NOTE: PROG_* slot indices are defined in kernel/include/tail_call_types.h
 * as enum upf_prog_index. That file is the single authoritative source,
 * shared by both kernel BPF programs and userspace translation units.
 *
 * User-space files that need PROG_SESSION_LOOKUP_IP, PROG_PDR_MATCH, etc.
 * must include tail_call_types.h directly:
 *
 *   #include "tail_call_types.h"   // enum upf_prog_index -- PROG_* slot
 * indices
 *
 * This file intentionally does NOT include tail_call_types.h to keep
 * upf_pipeline_config.h free of kernel/include/ dependencies so it
 * remains safely includable from control/ without BPF headers.
 */

#endif  // UPF_PIPELINE_CONFIG_H_
