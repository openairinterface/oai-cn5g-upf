/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef __SDF_TYPES_H__
#define __SDF_TYPES_H__

#include "linux/custom_types.h"

/* ==========================================================================
 * TC classid minor-ID helper
 * ========================================================================== */

/**
 * @brief Generate a unique 16-bit TC classid minor ID from SEID + QFI.
 *
 * Used to assign an HTB class to a QoS flow so the TC BPF classifier
 * (qer_tc_kern.c) can steer packets to the correct shaping queue.
 *
 * The hash avoids modulo (no division in BPF) and ensures the result
 * is in [1, 9999] (0 is reserved by TC).
 *
 * @param seid  PFCP Session Endpoint Identifier (64-bit)
 * @param qfi   QoS Flow Identifier (8-bit, typically 1-63)
 * @return 16-bit minor ID in range [1, 9999]
 */
static inline u16 generate_minor_id(u64 seid, u8 qfi) {
  u16 hash     = (u16) (seid ^ (seid >> 16) ^ (seid >> 32) ^ (seid >> 48));
  u16 minor_id = (hash + (qfi * 37)) & 0xFFFF;

  /* Limit to 0-9999 and avoid 0 (TC reserved) */
  minor_id = (minor_id > 9999) ? 9999 : minor_id;
  return minor_id ? minor_id : 1;
}

/* ==========================================================================
 * IP subnet
 * ========================================================================== */

/**
 * @brief IP address + prefix-mask pair for SDF source/destination matching.
 *
 * type == 0: wildcard (match any IP — ip and mask are ignored)
 * type == 1: IPv4     (lower 32 bits of ip and mask are used)
 * type == 2: IPv6     (all 128 bits of ip and mask are used)
 */
struct ip_subnet {
  u8 type;   /**< 0=any, 1=ipv4, 2=ipv6                            */
  u128 ip;   /**< IP address (lower 32b for v4, all 128b for v6)   */
  u128 mask; /**< Prefix mask (applied before comparison)           */
};

/* ==========================================================================
 * Port range
 * ========================================================================== */

/**
 * @brief L4 port range for SDF filter matching.
 *
 * A packet matches if its port is in [lower_bound, upper_bound].
 * When not specified in the SDF filter: lower_bound=0, upper_bound=65535.
 */
struct port_range {
  u16 lower_bound; /**< Inclusive lower port bound (0 = unspecified)  */
  u16 upper_bound; /**< Inclusive upper port bound (65535 = any)      */
};

/* ==========================================================================
 * Packet filter (5-tuple)
 * ========================================================================== */

/**
 * @brief 5-tuple extracted from a packet for SDF filter matching.
 *
 * Populated by extract_5tuple() in protocols/ip.h during PDR matching.
 * Matched against sdf_filtr entries in sdf_filters_map.
 *
 * 3GPP TS 29.244 §8.2.5 — SDF Filter IE fields:
 *   src_ip, dst_ip, protocol, src_port, dst_port
 */
struct packet_filter {
  u32 src_ip;   /**< Source IPv4 address (host byte order)       */
  u32 dst_ip;   /**< Destination IPv4 address (host byte order)  */
  u16 protocol; /**< IP protocol number (IANA)                   */
  u16 src_port; /**< Source L4 port (host byte order)            */
  u16 dst_port; /**< Destination L4 port (host byte order)       */
} __attribute__((aligned(8)));

/* ==========================================================================
 * Session + QFI map key
 * ========================================================================== */

/**
 * @brief Composite map key combining SEID and QFI.
 *
 * Used as the key for sdf_filters_map.
 * Identifies a specific SDF filter within a PFCP session.
 */
struct session_qfi {
  u64 seid; /**< PFCP Session Endpoint Identifier */
  u8 qfi;   /**< QoS Flow Identifier              */
};

/* ==========================================================================
 * SDF filter rule
 * ========================================================================== */

/**
 * @brief Full SDF filter rule stored in sdf_filters_map.
 *
 * Populated by control plane during PFCP Session Establishment
 * (TS 29.244 §7.5.2) from the SDF Filter IE (§8.2.5).
 *
 * A packet matches this filter when:
 *   protocol matches (or filter protocol == 0 for wildcard)
 *   src_addr:  (pkt_src_ip & mask) == (filter_ip & mask)
 *   dst_addr:  (pkt_dst_ip & mask) == (filter_ip & mask)
 *   src_port:  pkt_src_port in [lower_bound, upper_bound]
 *   dst_port:  pkt_dst_port in [lower_bound, upper_bound]
 */
struct sdf_filtr {
  u16 protocol;               /**< IP protocol (0 = wildcard)       */
  struct ip_subnet src_addr;  /**< Source IP + mask                 */
  struct port_range src_port; /**< Source port range                */
  struct ip_subnet dst_addr;  /**< Destination IP + mask            */
  struct port_range dst_port; /**< Destination port range           */
  struct session_qfi session; /**< Owning session + QFI (metadata)  */
};

#endif /* __SDF_TYPES_H__ */