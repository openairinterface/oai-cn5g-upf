/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef PACKET_CONTEXT_H
#define PACKET_CONTEXT_H

#include <linux/types.h>
#include <linux/if_ether.h>

/* ========================================================================== */
/*                          SESSION / DIRECTION TYPE */
/* ========================================================================== */

/**
 * @brief PDU session type and traffic direction
 *
 * Encodes both the PDU session type (IP or Ethernet per TS 23.501 §5.6.10)
 * and the traffic direction (uplink or downlink per TS 23.501 §5.8.2).
 *
 * - IP PDU sessions:  UE ↔ Data Network via IPv4/IPv6
 * - ETH PDU sessions: UE ↔ Data Network via L2 Ethernet frames
 */
enum session_type {
  SESSION_TYPE_IP_UPLINK    = 0, /**< IP PDU,  N3→N6 (UL) */
  SESSION_TYPE_IP_DOWNLINK  = 1, /**< IP PDU,  N6→N3 (DL) */
  SESSION_TYPE_ETH_UPLINK   = 2, /**< ETH PDU, N3→N6 (UL) */
  SESSION_TYPE_ETH_DOWNLINK = 3, /**< ETH PDU, N6→N3 (DL) */
};

#define IS_UPLINK(st)                                                          \
  ((st) == SESSION_TYPE_IP_UPLINK || (st) == SESSION_TYPE_ETH_UPLINK)
#define IS_DOWNLINK(st)                                                        \
  ((st) == SESSION_TYPE_IP_DOWNLINK || (st) == SESSION_TYPE_ETH_DOWNLINK)
#define IS_IP_PDU(st)                                                          \
  ((st) == SESSION_TYPE_IP_UPLINK || (st) == SESSION_TYPE_IP_DOWNLINK)
#define IS_ETH_PDU(st)                                                         \
  ((st) == SESSION_TYPE_ETH_UPLINK || (st) == SESSION_TYPE_ETH_DOWNLINK)

/* ========================================================================== */
/*                     PER-SESSION RULE ENABLE FLAGS                          */
/* ========================================================================== */

/**
 * @brief Bitmask of active PFCP rules per session
 *
 * Populated by the control plane during PFCP Session Establishment
 * (TS 29.244 §7.2.2) or PFCP Session Modification (TS 29.244 §7.2.4).
 * Stored in session_rules_enabled_map, cached in pctx->rules_enabled
 * by session lookup. Each tail call program checks its flag to decide
 * whether to process or skip — disabled rules cost zero tail calls.
 *
 * Default: 0 (all rules disabled → plain forwarding only).
 */
#define RULE_QER_ENABLED (1U << 0) /**< QER: Gate + MBR/GBR (§8.2.40-43)  */
#define RULE_URR_ENABLED (1U << 1) /**< URR: Usage Reporting (§8.2.44-48)  */
#define RULE_BAR_ENABLED (1U << 2) /**< BAR: Buffering + DDN (§8.2.49-50)  */
#define RULE_MAR_ENABLED (1U << 3) /**< MAR: ATSSS Steering (§8.2.123-125) */

/* ========================================================================== */
/*                              FINAL ACTION                                  */
/* ========================================================================== */

/**
 * @brief Terminal XDP action determined by the processing chain
 *
 * Set by FAR after applying the forwarding parameters (Outer Header Creation,
 * Outer Header Removal — TS 29.244 §8.2.56/§8.2.57). Downstream programs
 * may override it:
 *   - QER: Gate Status IE closed → DROP (TS 29.244 §8.2.41)
 *   - URR: Volume Quota exhausted → DROP (TS 29.244 §8.2.46)
 *   - MAR: Access steering → change redirect target (TS 29.244 §8.2.123)
 *
 * The last enabled program in the chain executes the action.
 */
enum final_action {
  FINAL_ACTION_REDIRECT_UL = 0, /**< bpf_redirect_map → N6 (UL) */
  FINAL_ACTION_REDIRECT_DL = 1, /**< bpf_redirect_map → N3 (DL) */
  FINAL_ACTION_PASS_TO_TC  = 2, /**< XDP_PASS → TC QoS shaping  */
  FINAL_ACTION_DROP        = 3, /**< XDP_DROP                    */
  FINAL_ACTION_PASS        = 4, /**< XDP_PASS → kernel stack     */
};

/* ========================================================================== */
/*                        PACKET CONTEXT STRUCTURE                            */
/* ========================================================================== */

/**
 * @brief Shared per-packet context for the BPF tail call processing chain
 */
struct packet_context {
  /* --- Set by entry point (upf_n3_entry / upf_n6_entry / eth variants) --- */
  __u32 session_type; /**< enum session_type                   */
  __u32 ue_ip;        /**< UE IP Address IE (§8.2.36),
                       *   host byte order (IP PDU only)        */
  __u8 qfi;           /**< QFI IE (§8.2.89), from GTP-U PDU
                       *   Session Container (UL) or PDR (DL)   */
  __u8 pad1[3];
  __u32 pkt_teid; /**< F-TEID IE (§8.2.3) from incoming
                   *   GTP-U header, UL only               */

  /* 5-tuple for SDF filter matching (IP DL only, §8.2.5) */
  __u32 pkt_filter_src_ip;   /**< Source IP (host byte order)         */
  __u32 pkt_filter_dst_ip;   /**< Destination IP (host byte order)    */
  __u16 pkt_filter_src_port; /**< Source port (host byte order)       */
  __u16 pkt_filter_dst_port; /**< Destination port (host byte order)  */
  __u8 pkt_filter_protocol;  /**< IP protocol (IANA number)           */
  __u8 pad2[3];

  /* --- Set by session lookup --- */
  __u64 seid;          /**< SEID (§7.2.2.1)                    */
  __u32 teid_ul;       /**< Uplink F-TEID (host byte order)    */
  __u32 teid_dl;       /**< Downlink F-TEID (host byte order)  */
  __u32 rules_enabled; /**< RULE_*_ENABLED bitmask              */

  /* --- Set by PDR match --- */
  __u32 pdr_id; /**< PDR ID IE (§8.2.21), Rule ID       */

  /* --- Set by FAR, read/overridden by downstream --- */
  __u32 final_action; /**< enum final_action                   */

  /* --- ETH PDU fields (set by upf_n3_eth_entry / upf_n6_eth_entry) --- */
  __u8 inner_eth_src[ETH_ALEN]; /**< Inner ETH source MAC (UL only)
                                 *   Used for MAC learning in
                                 *   session_lookup_eth              */
  __u8 inner_eth_dst[ETH_ALEN]; /**< Inner ETH dest MAC (UL only)
                                 *   Used for broadcast/multicast
                                 *   detection in far_apply          */
  __u16 inner_eth_proto;        /**< Inner ETH ethertype                 */
  __u16 pad3;
  __u32 gnb_ipv4; /**< gNB outer src IP (network byte order)
                   *   Used for MAC learning table entry
                   *   (DL encap destination)              */
  /*
   * pdr_mar_id: MAR ID from matched PDR (§8.2.123) — V17.10.0 addition.
   * 0 = PDR has no associated MAR (single-access session).
   * Non-zero: identifies which MAR rule applies; used by mar_apply.c
   * to select the ATSSS steering configuration.
   */
  __u16 pdr_mar_id; /**< MAR ID from matched PDR (§8.2.123); 0 = none */
  __u16 pad4;
  /*
   * Future fields — uncomment when implementing:
   *
   * __u32 urr_vol_bytes;     Volume Measurement IE (§8.2.45)
   * __u32 urr_id;            URR ID IE (§8.2.54)
   * __u32 bar_id;            BAR ID IE (§8.2.57)
   */
};

#endif /* PACKET_CONTEXT_H */
