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
 * @date 2025
 *
 * Lives in include/ — the only folder visible to control/, user/, and kernel/
 * without cross-folder dependencies.
 *
 * Defines:
 *   - PduSessionType       — IP or Ethernet entry program selection
 *   - PipelineFeatureFlags — which optional PROG_ARRAY slots to load
 *   - ProgIndex            — PROG_ARRAY slot assignments
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
 * @see ProgIndex for slot assignments
 * @see kernel/xdp/tail_call_dispatch.h — kernel-side enum (must stay in sync)
 */
struct PipelineFeatureFlags {
  bool enable_qos = false;  ///< PROG_QER  — QoS gate + MBR/GBR enforcement
  bool enable_urr = false;  ///< PROG_URR  — volume/time usage reporting
  bool enable_bar = false;  ///< PROG_BAR  — DL buffering + DDN notification
  bool enable_mar = false;  ///< PROG_MAR  — ATSSS multi-access steering
  bool enable_framed_routing = false;  ///< PROG_FRAMED_ROUTING — per-UE routes
  PduSessionType pdu_type    = PduSessionType::IP;  ///< Entry program set
};

// ==========================================================================
// PROG_ARRAY Slot Indices
// ==========================================================================

/**
 * @brief PROG_ARRAY slot assignments for feature_dispatch_map
 *
 * MUST match enum upf_prog_index in kernel/xdp/tail_call_dispatch.h exactly.
 * Any mismatch causes the kernel to tail-call the wrong program or miss a
 * stage.
 *
 * Mandatory (always populated):   SESSION_LOOKUP, PDR_MATCH, FAR
 * Optional (gated by flags):      QER, URR, BAR, MAR, FRAMED_ROUTING
 * ETH-PDU-only:                   ETH_PDU_BROADCAST
 */
enum ProgIndex : uint32_t {
  PROG_SESSION_LOOKUP    = 0,  ///< IP or Ethernet session lookup
  PROG_PDR_MATCH         = 1,  ///< PDR precedence matching
  PROG_FAR               = 2,  ///< Forwarding Action Rule apply
  PROG_QER               = 3,  ///< QoS Enforcement Rule (optional)
  PROG_URR               = 4,  ///< Usage Reporting Rule (optional)
  PROG_BAR               = 5,  ///< Buffering Action Rule (optional)
  PROG_MAR               = 6,  ///< Multi-Access Rule / ATSSS (optional)
  PROG_FRAMED_ROUTING    = 7,  ///< Per-UE framed routing (optional)
  PROG_ETH_PDU_BROADCAST = 8,  ///< Ethernet PDU ARP/broadcast (ETH only)
  PROG_MAX               = 16  ///< PROG_ARRAY capacity
};

#endif  // UPF_PIPELINE_CONFIG_H_