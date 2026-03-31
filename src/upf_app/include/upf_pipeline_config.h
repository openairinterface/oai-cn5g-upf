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

/**
 * @file upf_pipeline_config.h
 * @brief BPF tail-call pipeline types shared across control/, user/, and
 * kernel/
 * @author OpenAirInterface
 * @date 2025 / 2026-03
 *
 * Changes (2026-03): Removed stale ProgIndex enum -- it duplicated
 *   enum upf_prog_index from kernel/include/tail_call_types.h with
 *   wrong values, causing redefinition errors. User-space files that
 *   need PROG_* slot indices must include tail_call_types.h directly.
 *   PduSessionType and PipelineFeatureFlags are unchanged.
 *
 * Lives in include/ — the only folder visible to control/, user/, and kernel/
 * without cross-folder dependencies.
 *
 * Defines:
 *   - PduSessionType       — IP or Ethernet entry program selection
 *   - PipelineFeatureFlags — which optional PROG_ARRAY slots to load
 *   - upf_prog_index       — PROG_* slot indices (in tail_call_types.h)
 *
 * These types are intentionally kept here and NOT in user/upf_xdp_user.h
 * because control/UserPlaneComponent and helpers/startup_banner need them
 * without being allowed to depend on user/.
 *
 * No dependency on upf_config.hpp or any generated skeleton header.
 * Safe to include anywhere.
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
