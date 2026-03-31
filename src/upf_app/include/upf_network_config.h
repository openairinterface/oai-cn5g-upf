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
 * @file upf_network_config.h
 * @brief Shared UPF network and feature-flag configuration
 * @author OpenAirInterface
 * @date 2025
 *
 * Lives in include/ so it is visible to kernel/, control/, and user/
 * without any cross-folder dependency.
 *
 * Contains:
 *   - NetworkConfig struct  — flat snapshot of the upf_config fields needed
 *                             outside of app/ (interfaces, IPs, flags, sizing)
 *   - upf::g_net_cfg        — the single global instance (defined in
 *                             control/Configuration.cpp, the sole writer)
 *   - upf::Get*()/Is*()     — inline convenience getters (zero overhead)
 *
 * Ownership
 * ---------
 *   Writer  : control/Configuration::BuildNetworkConfig()
 *             Called once by UserPlaneComponent::Setup() before any BPF work.
 *   Readers : user/, kernel include headers, control/ (except Configuration)
 *
 * No dependency on upf_config.hpp — safe to include anywhere.
 */

#ifndef UPF_NETWORK_CONFIG_H_
#define UPF_NETWORK_CONFIG_H_

#include <cstdint>
#include <string>

namespace upf {

// ==========================================================================
// Shared configuration struct
// ==========================================================================

/**
 * @struct NetworkConfig
 * @brief Flat snapshot of the upf_config fields used outside of app/.
 *
 * Populated once by control/Configuration.cpp after upf_cfg is loaded.
 * All fields map 1:1 to their upf_cfg counterparts (documented below).
 */
struct NetworkConfig {
  // ---- Network interfaces (3GPP TS 23.501 Section 5.8.2) ----------------

  /// N3 (GTP-U) interface name   — upf_cfg.n3.if_name
  std::string n3_iface;

  /// N6 (Data Network) interface name — upf_cfg.n6.if_name
  std::string n6_iface;

  // ---- IPv4 addresses ----------------------------------------------------

  /// UPF N3 interface address (toward gNodeB)  — upf_cfg.n3.addr4.s_addr
  /// @see 3GPP TS 23.501 Section 5.8.2.2
  uint32_t n3_ip = 0;

  /// UPF N6 interface address (toward DN)       — upf_cfg.n6.addr4.s_addr
  /// @see 3GPP TS 23.501 Section 5.8.2.3
  uint32_t n6_ip = 0;

  /// Remote Data Network (DN) address           — upf_cfg.remote_n6.s_addr
  /// Used as the ARP target on N6 to resolve the next-hop MAC.
  uint32_t dn_ip = 0;

  // ---- Feature flags -----------------------------------------------------

  /// eBPF/XDP datapath acceleration — upf_cfg.enable_bpf_datapath
  bool bpf_datapath = false;

  /// TC-BPF QoS enforcement (QER) — upf_cfg.enable_qer
  bool qos = false;

  /// Usage Reporting Rule support — upf_cfg.enable_urr
  bool urr = false;

  /// Buffering Action Rule support — upf_cfg.enable_bar
  bool bar = false;

  /// Multi-Access Rule / ATSSS support — upf_cfg.enable_mar
  bool mar = false;

  /// Framed routing (RFC 2865 / 3GPP TS 29.061) — upf_cfg.enable_framed_routing
  bool framed_routing = false;

  // ---- Session type ------------------------------------------------------

  /// PDU session type string ("ipv4", "ipv6", "ethernet") —
  /// upf_cfg.pdu_session_type
  std::string pdu_session_type;

  // ---- N4 (PFCP control plane) interface ---------------------------------
  /// N4 (PFCP) interface name    — upf_cfg.n4.if_name
  std::string n4_iface;
  /// UPF N4 interface IPv4       — upf_cfg.n4.addr4.s_addr
  uint32_t n4_ip = 0;
  /// N3 GTP-U listen port        — upf_cfg.n3.port
  uint16_t n3_port = 0;
  /// N4 PFCP listen port         — upf_cfg.n4.port
  uint16_t n4_port = 0;
  // /// N6 data-plane listen port   — upf_cfg.n6.port
  // uint16_t n6_port = 0;

  // ---- BPF map sizing -------------------------------------------------------
  /// Maximum concurrent PDU sessions   — upf_cfg.max_pdu_sessions
  uint32_t max_pdu_sessions = 0;
  /// Maximum PDRs per PDU session      — upf_cfg.max_pdrs_per_pdu_session
  uint32_t max_pdrs_per_pdu_session = 0;
  /// Maximum SDF filters per session   —
  /// upf_cfg.max_sdf_filters_per_pdu_session
  uint32_t max_sdf_filters_per_pdu_session = 0;
  /// Maximum UPF interfaces tracked    — upf_cfg.max_upf_interfaces
  uint32_t max_upf_interfaces = 0;
  /// Maximum redirect (egress) interfaces — upf_cfg.max_upf_redirect_interfaces
  uint32_t max_upf_redirect_interfaces = 0;
  /// Maximum ARP table entries         — upf_cfg.max_arp_entries
  uint32_t max_arp_entries = 0;
};

// ==========================================================================
// Global instance — defined in control/Configuration.cpp
// ==========================================================================

/**
 * @brief The single shared NetworkConfig instance.
 *
 * Populated by control/Configuration.cpp during startup.
 * All other modules access this through the inline getters below.
 */
extern NetworkConfig g_net_cfg;

// ==========================================================================
// Inline convenience getters
// ==========================================================================

// ---- Interface names -------------------------------------------------------

/** @return N3 (GTP-U) Linux interface name */
inline const std::string& GetN3Iface() {
  return g_net_cfg.n3_iface;
}

/** @return N4 (PFCP toward SMF) Linux interface name */
inline const std::string& GetN4Iface() {
  return g_net_cfg.n4_iface;
}

/** @return N6 (Data Network) Linux interface name */
inline const std::string& GetN6Iface() {
  return g_net_cfg.n6_iface;
}

// ---- IPv4 addresses --------------------------------------------------------

/**
 * @return UPF N3 interface IPv4 address
 * @see 3GPP TS 23.501 Section 5.8.2.2
 */
inline uint32_t GetN3Ip() {
  return g_net_cfg.n3_ip;
}

/**
 * @return UPF N6 interface IPv4 address
 * @see 3GPP TS 23.501 Section 5.8.2.3
 */
inline uint32_t GetN6Ip() {
  return g_net_cfg.n6_ip;
}

/** @ return UPF N4 interface IPv4 address */
inline uint32_t GetN4Ip() {
  return g_net_cfg.n4_ip;
}

/**
 * @return Remote Data Network (DN) IPv4 address (ARP target on N6)
 * @see 3GPP TS 23.501 Section 5.8.2.3
 */
inline uint32_t GetDnIp() {
  return g_net_cfg.dn_ip;
}

/** @return N3 GTP-U listen port */
inline uint16_t GetN3Port() {
  return g_net_cfg.n3_port;
}

/** @return N4 PFCP listen port */
inline uint16_t GetN4Port() {
  return g_net_cfg.n4_port;
}

// /** @return N6 data-plane listen port */
// inline uint16_t GetN6Port() {
//   return g_net_cfg.n6_port;
// }
// ---- Feature flags ---------------------------------------------------------

/** @return true if eBPF/XDP datapath acceleration is enabled */
inline bool IsBpfDatapathEnabled() {
  return g_net_cfg.bpf_datapath;
}

/** @return true if TC-BPF QoS enforcement (QER) is enabled */
inline bool IsQosEnabled() {
  return g_net_cfg.qos;
}

/** @return true if Usage Reporting Rules (URR) are enabled */
inline bool IsUrrEnabled() {
  return g_net_cfg.urr;
}

/** @return true if Buffering Action Rules (BAR) are enabled */
inline bool IsBarEnabled() {
  return g_net_cfg.bar;
}

/** @return true if Multi-Access Rules / ATSSS (MAR) are enabled */
inline bool IsMarEnabled() {
  return g_net_cfg.mar;
}

/** @return true if framed routing is enabled (RFC 2865 / 3GPP TS 29.061) */
inline bool IsFramedRoutingEnabled() {
  return g_net_cfg.framed_routing;
}

// ---- Session type ----------------------------------------------------------

/** @return PDU session type string ("ipv4", "ipv6", "ethernet") */
inline const std::string& GetPduSessionType() {
  return g_net_cfg.pdu_session_type;
}

// ---- BPF map sizing --------------------------------------------------------

/** @return Maximum concurrent PDU sessions */
inline uint32_t GetMaxPduSessions() {
  return g_net_cfg.max_pdu_sessions;
}

/** @return Maximum PDRs per PDU session */
inline uint32_t GetMaxPdrsPerSession() {
  return g_net_cfg.max_pdrs_per_pdu_session;
}

/** @return Maximum SDF filters per PDU session */
inline uint32_t GetMaxSdfFiltersPerSession() {
  return g_net_cfg.max_sdf_filters_per_pdu_session;
}

/** @return Maximum UPF interfaces tracked in BPF maps */
inline uint32_t GetMaxUpfInterfaces() {
  return g_net_cfg.max_upf_interfaces;
}

/** @return Maximum redirect (egress) interfaces */
inline uint32_t GetMaxUpfRedirectInterfaces() {
  return g_net_cfg.max_upf_redirect_interfaces;
}

/** @return Maximum ARP table entries */
inline uint32_t GetMaxArpEntries() {
  return g_net_cfg.max_arp_entries;
}

}  // namespace upf

#endif  // UPF_NETWORK_CONFIG_H_
