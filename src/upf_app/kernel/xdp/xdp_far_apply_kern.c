/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#define KBUILD_MODNAME far_apply

/* ========================================================================== */
/*                              SYSTEM INCLUDES                               */
/* ========================================================================== */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>
#include <string.h>

/* ========================================================================== */
/*                             PROJECT INCLUDES                               */
/* ========================================================================== */

#include "linux/custom_types.h"
#include "utils/csum.h"
#include "utils/logger.h"
#include "utils/bpf_utils.h"
#include "utils/types.h"

/* Protocols */
#include "protocols/eth.h"
#include "protocols/gtpu.h"

/* PFCP structures */
#include "pfcp/pfcp_far.h"
#include "pfcp/pfcp_pdr.h"
#include "ie/group_ie/pdi.h"

/* Maps and definitions */
#include "pipeline_maps.h"
#include "interfaces_maps.h"
#include "arp_maps.h"
#include "eth_pdu_maps.h"
#include "tail_call_dispatcher.h"
#include "stats_maps.h"
#include "stats_types.h"

#define IP_DF 0x4000 /* Don't Fragment; Fragment offset = 0 */

/* AF_INET defined directly to avoid pulling in <sys/socket.h>, a userspace
 * header not available in BPF compilation (same convention as
 * utils/mac_resolution.h). Used for the N6 next-hop bpf_fib_lookup(). */
#ifndef AF_INET
#define AF_INET 2
#endif

/* ========================================================================== */
/*                          GLOBAL CACHE VARIABLES                            */
/* ========================================================================== */

/**
 * @brief Cached UPF N3 source IP.
 *
 * The UPF's own N3 IP is used as the outer source IP for every GTP-U
 * encapsulation. It never changes after process start, so caching it
 * avoids a per-packet upf_interface_map lookup.
 *
 * Next-hop MACs are NOT cached: the harmonised arp_table_map convention
 * is "key = peer IP" (multi-gNB / multi-DN deployments need one entry per
 * peer), so a single static slot would be unsound. Per-packet HASH lookup
 * in arp_table_map is cheap enough on the hot path.
 */
static u32 cached_n3_ip;
static bool n3_cache_valid;

/* ========================================================================== */
/*               GTP-U ENCAPSULATION — DOWNLINK (TS 29.281 §5.1)             */
/* ========================================================================== */

/**
 * @brief Create GTP-U outer headers for downlink packets
 *
 * Applies Outer Header Creation (TS 29.244 §8.2.56):
 * - Outer Ethernet header (copied from inner, MAC updated for N3 next-hop)
 * - Outer IPv4 header (UPF N3 IP → gNB IP from FAR)
 * - Outer UDP header (port 2152, IANA assigned for GTP-U)
 * - GTP-U header with TEID from FAR (TS 29.281 §5.1)
 * - GTP-U extension: PDU Session Container with QFI (TS 29.281 §5.5.3.3)
 *
 * Packet transformation:
 *   Before: [ETH][IP][TCP/UDP][payload]
 *   After:
 * [ETH'][IP-outer][UDP:2152][GTP-U][PDU-Sess-Container][IP][TCP/UDP][payload]
 *
 * @param ctx XDP context
 * @param far FAR with Outer Header Creation parameters
 * @param qfi QoS Flow Identifier for PDU Session Container
 * @return RET_SUCCESS, RET_DROP, or RET_FAILURE
 */
static __always_inline u32
gtpu_encap_ipv4(struct xdp_md* ctx, struct pfcp_far* far, u8 qfi) {
  /* Expand headroom for GTP-U encapsulation */
  if (bpf_xdp_adjust_head(ctx, (int32_t) -GTP_ENCAPSULATED_SIZE)) {
    bpf_debug(
        "Outer Header Creation: "
        "Failed to adjust head");
    return RET_DROP;
  }

  void* data     = (void*) (long) ctx->data;
  void* data_end = (void*) (long) ctx->data_end;

  /* Cache UPF N3 source IP (used as outer ip_saddr below). It never changes,
   * so caching is fine. */
  if (!n3_cache_valid) {
    reference_point_t iface_key = N3_INTERFACE;
    struct interface_config* iface =
        bpf_map_lookup_elem(&upf_interface_map, &iface_key);

    if (!iface) {
      bpf_debug("N3 interface not configured");
      return RET_FAILURE;
    }
    cached_n3_ip   = iface->ipv4_address;
    n3_cache_valid = true;
  }

  /* Resolve next-hop MAC PER PACKET, keyed by the gNB IP from the FAR.
   *
   * Userspace (SessionProgramManager::UpdateArpTableForN3) writes
   * arp_table_map[gNB_ip] = {gNB_MAC, gNB_ip}. The previous code looked up
   * by `cached_n3_ip` (UPF's own N3 IP) which is never a key in the map
   * since the user-side fix at SessionProgramManager.cpp:2231 -- so the
   * lookup silently failed and the GTP-U packet left demo-n3 with a zero
   * destination MAC, dropped by the bridge before reaching the gNB.
   *
   * Caching the MAC by `cached_n3_ip` was also unsound for multi-gNB
   * deployments (one cache slot, many possible peers). Doing the lookup
   * per-packet costs one HASH map_lookup_elem -- cheap on the hot path. */
  u32 next_hop_n3_ip =
      far->forwarding_parameters.outer_header_creation.ipv4_address.s_addr;
  struct arp_entry* arp_n3 =
      bpf_map_lookup_elem(&arp_table_map, &next_hop_n3_ip);
  if (!arp_n3) {
    bpf_debug(
        "N3 next-hop MAC not found in ARP table for gNB %pI4", &next_hop_n3_ip);
    return RET_FAILURE;
  }

  /*
 |----------------------------------------------------------------|
 |------------------ Build outer Ethernet header -----------------|
 |----------------------------------------------------------------|
 */
  struct ethhdr* eth_outer = data;

  if ((void*) (eth_outer + 1) > data_end) {
    bpf_debug("Error: Invalid Ethernet header");
    return RET_DROP;
  }

  struct ethhdr* eth_inner = data + GTP_ENCAPSULATED_SIZE;

  if ((void*) (eth_inner + 1) > data_end) {
    bpf_debug("Error: Invalid Ethernet copy header");
    return RET_DROP;
  }

  /* Copy inner Ethernet header to outer position */
  __builtin_memcpy(eth_outer, eth_inner, sizeof(*eth_outer));

  /* Update destination MAC to N3 next-hop (gNB) */
  __builtin_memcpy(eth_outer->h_dest, arp_n3->mac_address, ETH_ALEN);

  /*
  |----------------------------------------------------------------|
  |--------------------- Build outer IP header --------------------|
  |----------------------------------------------------------------|
  */
  struct iphdr* ip_outer = (void*) (eth_outer + 1);

  if ((void*) (ip_outer + 1) > data_end) {
    bpf_debug("Error: Invalid outer IP header");
    return RET_DROP;
  }

  struct iphdr* ip_inner = (void*) ip_outer + GTP_ENCAPSULATED_SIZE;

  if ((void*) (ip_inner + 1) > data_end) {
    bpf_debug("Error: Invalid inner IP header");
    return RET_DROP;
  }

  ip_outer->version = 4;
  ip_outer->ihl     = 5; /* No options */
  ip_outer->tos     = 0; /* TODO: Copy from inner or map from QFI */
  ip_outer->tot_len =
      bpf_htons(bpf_ntohs(ip_inner->tot_len) + GTP_ENCAPSULATED_SIZE);
  ip_outer->id       = 0;                /* No fragmentation */
  ip_outer->frag_off = bpf_htons(IP_DF); /* Don't fragment */
  ip_outer->ttl      = 64;
  ip_outer->protocol = IPPROTO_UDP;
  ip_outer->check    = 0;
  ip_outer->saddr    = cached_n3_ip;
  ip_outer->daddr =
      far->forwarding_parameters.outer_header_creation.ipv4_address.s_addr;

  bpf_debug(
      "GTP-U encap: outer IP ( ip_saddr, ip_daddr ) : ( %pI4, %pI4 )",
      &ip_outer->saddr, &ip_outer->daddr);

  /*
   |----------------------------------------------------------------|
   |-------------------- Build outer UDP header --------------------|
   |----------------------------------------------------------------|
   */
  struct udphdr* udp_outer = (void*) (ip_outer + 1);

  if ((void*) (udp_outer + 1) > data_end) {
    bpf_debug("Error: Invalid outer UDP header");
    return RET_DROP;
  }

  udp_outer->source = bpf_htons(GTP_UDP_PORT);
  udp_outer->dest   = bpf_htons(GTP_UDP_PORT);
  udp_outer->len    = bpf_htons(
      bpf_ntohs(ip_inner->tot_len) + sizeof(*udp_outer) +
      sizeof(struct gtpuhdr) + sizeof(struct gtpu_extn_pdu_session_container));
  udp_outer->check = 0; /* UDP checksum optional for IPv4 */

  /*
  |----------------------------------------------------------------|
  |----------------------- Build GTP-U header ---------------------|
  |----------------------------------------------------------------|
  */

  /* Build GTP-U header (TS 29.281 §5.1) */
  struct gtpuhdr* gtpu = (void*) (udp_outer + 1);

  if ((void*) (gtpu + 1) > data_end) {
    bpf_debug("Error: Invalid GTP-U header");
    return RET_DROP;
  }

  u8 flags = GTP_EXT_FLAGS; /* Version=1, PT=1, E=1 */

  __builtin_memcpy(gtpu, &flags, sizeof(u8));
  gtpu->message_type   = GTPU_G_PDU;
  gtpu->message_length = bpf_htons(
      bpf_ntohs(ip_inner->tot_len) +
      sizeof(struct gtpu_extn_pdu_session_container) + 4);
  gtpu->teid = bpf_htonl(far->forwarding_parameters.outer_header_creation.teid);
  gtpu->sequence      = GTP_SEQ;
  gtpu->pdu_number    = GTP_PDU_NUMBER;
  gtpu->next_ext_type = GTP_NEXT_EXT_TYPE;

  bpf_debug("GTP-U TEID: 0x%x", bpf_ntohl(gtpu->teid));

  /*
  |----------------------------------------------------------------|
  |--------------- Build GTP-U extension header -------------------|
  |----------------------------------------------------------------|
  */
  /* Build PDU Session Container extension (TS 29.281 §5.5.3.3) */
  struct gtpu_extn_pdu_session_container* gtpu_ext = (void*) (gtpu + 1);

  if ((void*) (gtpu_ext + 1) > data_end) {
    bpf_debug("Error: Invalid GTP-U extension header");
    return RET_DROP;
  }

  gtpu_ext->message_length = GTP_EXT_MSG_LEN;
  gtpu_ext->pdu_type       = GTP_EXT_PDU_TYPE;
  gtpu_ext->qfi            = qfi;
  gtpu_ext->next_ext_type  = GTP_EXT_NEXT_EXT_TYPE;

  /*
  |----------------------------------------------------------------|
  |---------------- Calculate outer IP checksum -------------------|
  |----------------------------------------------------------------|
  */
  __wsum csum = pcn_csum_diff(0, 0, (__be32*) ip_outer, sizeof(*ip_outer), 0);

  int ret = pcn_l3_csum_replace(ctx, IP_CSUM_OFFSET, 0, csum, 0);

  if (ret) {
    bpf_debug("Error: Invalid Checksum Calculation %d", ret);
  }
  bpf_debug("GTP-U encapsulation complete");
  return RET_SUCCESS;
}

/* ========================================================================== */
/*            GTP-U DECAPSULATION — UPLINK (TS 29.244 §8.2.57)               */
/* ========================================================================== */

/**
 * @brief Remove GTP-U outer headers from uplink packets
 *
 * Applies Outer Header Removal (TS 29.244 §8.2.57):
 * - Strips outer ETH, IP, UDP, GTP-U, and extension headers
 * - Copies inner Ethernet header to outer position
 * - Updates destination MAC for N6 next-hop forwarding
 *
 * Packet transformation:
 *   Before: [ETH][IP-outer][UDP:2152][GTP-U][PDU-Sess-Container][IP][payload]
 *   After:  [ETH'][IP][payload]
 *
 * @param ctx XDP context
 * @param far FAR (must have FORW flag set in Apply Action)
 * @return RET_SUCCESS, RET_DROP, or RET_FAILURE
 */
static __always_inline u32
gtpu_decap_ipv4(struct xdp_md* ctx, struct pfcp_far* far) {
  void* data     = (void*) (long) ctx->data;
  void* data_end = (void*) (long) ctx->data_end;

  struct ethhdr* eth_outer = data;

  if ((void*) (eth_outer + 1) > data_end) {
    bpf_debug("Error: Invalid Ethernet header");
    return RET_DROP;
  }

  /* Verify FAR has forward action (§8.2.26 bit 1) */
  if (!far->apply_action.forw) {
    bpf_debug("Apply Action: FORW bit not set");
    return RET_FAILURE;
  }

  bpf_debug("Outer Header Removal: GTP-U decapsulation");

  /* Get inner ethernet header position */
  struct ethhdr* eth_inner = (void*) (data + GTP_ENCAPSULATED_SIZE);

  if ((void*) (eth_inner + 1) > data_end) {
    bpf_debug("Error: Invalid Ethernet copy header");
    return RET_DROP;
  }

  /* Copy outer ethernet to inner position */
  __builtin_memcpy(eth_inner, eth_outer, sizeof(*eth_inner));

  /* Resolve the N6 next-hop MAC dynamically.
   *
   * The UPF is deliberately NOT a router: off-subnet uplink (e.g. a UE
   * reaching the internet, dst 8.8.8.8) is handed to the N6 gateway
   * (oai-ext-dn), which owns SNAT + MTU/fragmentation. Since there may be an
   * L2 network between the UPF and oai-ext-dn, the next-hop is NOT fixed and
   * must be resolved from the routing table -- never assumed to be the inner
   * destination IP.
   *
   *   1. Primary  -- kernel FIB (bpf_fib_lookup): returns the true next-hop
   *      MAC for the destination (the gateway towards oai-ext-dn for routed
   *      dst, or the peer itself when directly connected, e.g. the DN during
   *      iperf). Rewrites both source and destination MAC on a hit.
   *   2. Fallback -- FIB miss (no route / neighbour not yet resolved): resolve
   *      the next-hop MAC from arp_table_map -- the same "arping" path the
   *      monolithic gtpu_decap_ipv4() relied on. On a FIB miss the kernel
   *      still rewrites fib.ipv4_dst to the next-hop gateway IP, which is the
   *      exact key userspace installs (UpdateArpTableForN6); fall back to the
   *      inner destination IP for directly-connected peers. */
  struct iphdr* inner_iph = (void*) ((u8*) eth_inner + sizeof(struct ethhdr));
  if ((void*) (inner_iph + 1) > data_end) {
    bpf_debug("Error: Invalid inner IP header for next-hop resolution");
    return RET_DROP;
  }

  struct bpf_fib_lookup fib = {};
  fib.family                = AF_INET;
  fib.tos                   = inner_iph->tos;
  fib.l4_protocol           = inner_iph->protocol;
  fib.tot_len               = bpf_ntohs(inner_iph->tot_len);
  fib.ipv4_src              = inner_iph->saddr;
  fib.ipv4_dst              = inner_iph->daddr;
  fib.ifindex               = ctx->ingress_ifindex;

  int fib_rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);

  if (fib_rc == BPF_FIB_LKUP_RET_SUCCESS) {
    /* Routing resolved the next-hop (handles routed dst across an L2 network
     * between the UPF and the N6 gateway). */
    __builtin_memcpy(eth_inner->h_dest, fib.dmac, ETH_ALEN);
    __builtin_memcpy(eth_inner->h_source, fib.smac, ETH_ALEN);
    bpf_debug("N6 next-hop: FIB hit, dst MAC %pM", eth_inner->h_dest);
  } else {
    /* FIB miss -> arp_table_map fallback ("arping"), keyed by the resolved
     * next-hop gateway IP, then the inner destination as a last resort. */
    u32 nh_ip                = fib.ipv4_dst ? fib.ipv4_dst : inner_iph->daddr;
    struct arp_entry* arp_n6 = bpf_map_lookup_elem(&arp_table_map, &nh_ip);
    if (!arp_n6) {
      u32 dst_ip = inner_iph->daddr;
      arp_n6     = bpf_map_lookup_elem(&arp_table_map, &dst_ip);
    }
    if (!arp_n6) {
      bpf_debug(
          "N6 next-hop: FIB miss (rc=%d) and no ARP entry for %pI4 -- dropping",
          fib_rc, &nh_ip);
      return RET_FAILURE;
    }
    __builtin_memcpy(eth_inner->h_dest, arp_n6->mac_address, ETH_ALEN);
    bpf_debug(
        "N6 next-hop: FIB miss (rc=%d), ARP fallback dst MAC %pM", fib_rc,
        eth_inner->h_dest);
  }

  /* Strip outer headers */
  if (bpf_xdp_adjust_head(ctx, GTP_ENCAPSULATED_SIZE)) {
    bpf_debug(
        "Outer Header Removal: "
        "Failed to adjust head");
    return RET_DROP;
  }

  bpf_debug("GTP-U decapsulation complete");
  return RET_SUCCESS;
}

/* ========================================================================== */
/*                        FAR APPLY ENTRY POINT                               */
/* ========================================================================== */

/**
 * @brief Apply Forwarding Action Rule
 *
 * Processes the Apply Action IE (TS 29.244 §8.2.26) bitmask. Uses
 * bitwise checks (not switch) because multiple flags may be set
 * simultaneously. Priority: DROP > FORW > BUFF > NOCP > DUPL.
 *
 * After encap/decap, sets pctx->final_action and dispatches to the
 * next enabled rule in the chain via dispatch_after_far().
 */
SEC("xdp")
int far_apply(struct xdp_md* ctx) {
  bpf_debug("=== FAR Apply ===");

  struct packet_context* pctx = GET_PACKET_CONTEXT();

  if (!pctx) {
    bpf_debug("Error: Failed to get packet context");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  struct pdrs_per_session pdr_key = {0};

  pdr_key.pdr_id                   = pctx->pdr_id;
  pdr_key.seid                     = pctx->seid;
  __attribute__((unused)) u64 seid = pctx->seid;
  __u32 flags                      = pctx->rules_enabled;

  struct rules_match_pdr* rules;

  if (IS_ETH_PDU(pctx->session_type))
    rules = bpf_map_lookup_elem(&eth_rules_match_pdr_map, &pdr_key);
  else
    rules = bpf_map_lookup_elem(&rules_match_pdr_map, &pdr_key);

  if (!rules) {
    bpf_debug("FAR: No rules for PDR (SEID = %llu)", seid);
    return xdp_stats_record_action(ctx, XDP_PASS);
  }

  /* Get FAR from rules */
  struct pfcp_far* far = &rules->far;

  if (!far || far->far_id.far_id == 0) {
    bpf_debug("FAR: Invalid FAR ID for SEID = %llu", seid);
    return xdp_stats_record_action(ctx, XDP_PASS);
  }

  bpf_debug("Applying FAR ID=%u for session %llu", far->far_id.far_id, seid);

  /*
   * Check each flag using bitwise AND (&) operator
   * We cannot use switch here because Apply Action is a bit field.
   * Example: if action=0x0A (FORW + NOCP), switch(0x0A) won't match
   * case APPLY_ACTION_FORW (0x02), but (0x0A & 0x02) correctly detects
   * that the FORWARD bit is set.
   */
  u8 action = *((u8*) &far->apply_action);

  /* -------------------------------------------------------------- */
  /*  Priority 1: DROP (§8.2.26 bit 0)                              */
  /* -------------------------------------------------------------- */
  if (action & PFCP_APPLY_ACTION_DROP) {
    bpf_debug("Apply Action: DROP ( SEID = %llu )", seid);
    pctx->final_action = FINAL_ACTION_DROP;

    /* Chain through URR for usage accounting even on DROP */
    dispatch_after_far(ctx, flags, false);

    /* All downstream disabled or tail call failed */
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  /* -------------------------------------------------------------- */
  /*  Priority 2: FORWARD (§8.2.26 bit 1)                           */
  /* -------------------------------------------------------------- */
  if (action & PFCP_APPLY_ACTION_FORW) {
    if (IS_ETH_PDU(pctx->session_type) && IS_UPLINK(pctx->session_type)) {
      /* ================================================ */
      /*  ETH PDU UL: Broadcast/Multicast or GTP strip    */
      /*  (TS 23.501 section 5.6.10.3)                    */
      /* ================================================ */

      /*
       * Check if inner dest MAC is broadcast/multicast.
       * If so, flood to all ETH PDU sessions via TC.
       */
      if (eth_is_bcast_or_mcast(
              pctx->inner_eth_dst, (const void*) ((long) ctx->data_end))) {
        bpf_debug(
            "ETH PDU UL FORW: Broadcast/multicast "
            "detected, pass to TC for fan-out");

        pctx->final_action = FINAL_ACTION_PASS_TO_TC;
        dispatch_after_far(ctx, flags, false);
        return xdp_stats_record_action(ctx, XDP_PASS);
      }

      /*
       * Unicast: strip GTP-U headers and forward inner
       * Ethernet frame to N6 (same decap as IP PDU).
       */
      bpf_debug("ETH PDU UL FORW: Unicast GTP strip");

      int ret = gtpu_decap_ipv4(ctx, far);

      if (ret != RET_SUCCESS) {
        bpf_debug("ETH GTP-U decap failed (ret=%d)", ret);
        return xdp_stats_record_action(
            ctx, (ret == RET_DROP) ? XDP_DROP : XDP_PASS);
      }

      pctx->final_action = FINAL_ACTION_REDIRECT_UL;
      bool qer_needed    = (flags & RULE_QER_ENABLED) != 0;
      dispatch_after_far(ctx, flags, qer_needed);

      bpf_debug("ETH PDU UL: Direct redirect to N6");
      return xdp_stats_record_action(
          ctx, bpf_redirect_map(&redirect_interfaces_map, UPLINK, 0));

    } else if (IS_UPLINK(pctx->session_type)) {
      /* ================================================ */
      /*  IP PDU UL: Outer Header Removal (§8.2.57) → N6         */
      /* ================================================ */
      bpf_debug(
          "Apply Action: FORW UL - "
          "Outer Header Removal");

      int ret = gtpu_decap_ipv4(ctx, far);

      if (ret != RET_SUCCESS) {
        bpf_debug("GTP-U decap failed (ret = %d)", ret);
        return xdp_stats_record_action(
            ctx, (ret == RET_DROP) ? XDP_DROP : XDP_PASS);
      }

      pctx->final_action = FINAL_ACTION_REDIRECT_UL;

      /* Dispatch: [URR] → [MAR] → redirect.
       *
       * QER is intentionally skipped on UL: there is no rate enforcement on
       * the uplink data path (no TC HTB on the N6 egress), so calling QER
       * would only do a UL-gate check that is OPEN in all production
       * configurations. URR is still chained (volume/time accounting is
       * direction-aware in 3GPP TS 29.244 §8.2.46) and MAR likewise. To
       * re-enable UL QER processing later, replace `false` with
       * `(flags & RULE_QER_ENABLED) != 0` and re-introduce a UL-QoS TC
       * stage.
       */
      dispatch_after_far(ctx, flags, false /* qer_needed -- UL skips QER */);

      /* No downstream tail call fired -- redirect directly to N6 */
      bpf_debug("UL: redirect to N6 (slot UPLINK)");
      return xdp_stats_record_action(
          ctx, bpf_redirect_map(&redirect_interfaces_map, UPLINK, 0));

    } else {
      /* ================================================ */
      /*  DL: Outer Header Creation (§8.2.56) → N3        */
      /* ================================================ */
      bpf_debug(
          "Apply Action: FORW DL - "
          "Outer Header Creation QFI = %u",
          pctx->qfi);

      int ret = gtpu_encap_ipv4(ctx, far, pctx->qfi);

      if (ret != RET_SUCCESS) {
        bpf_debug("GTP-U encap failed ( ret=%d )", ret);
        return xdp_stats_record_action(
            ctx, (ret == RET_DROP) ? XDP_DROP : XDP_PASS);
      }

      bool qer_needed = (flags & RULE_QER_ENABLED) != 0;

      if (qer_needed) {
        pctx->final_action = FINAL_ACTION_PASS_TO_TC;
        bpf_debug("QER enabled - TC QoS path");
      } else {
        pctx->final_action = FINAL_ACTION_REDIRECT_DL;
        bpf_debug("QER disabled - direct N3 redirect");
      }

      /* Dispatch: [QER] → [URR] → [MAR] → execute */
      dispatch_after_far(ctx, flags, qer_needed);

      /* All disabled — execute final action now */
      EXECUTE_FINAL_ACTION(ctx, pctx);
    }
  }

  /* -------------------------------------------------------------- */
  /*  Priority 3: BUFFER (§8.2.26 bit 2) → BAR                     */
  /* -------------------------------------------------------------- */
  if (action & PFCP_APPLY_ACTION_BUFF) {
    bpf_debug("Apply Action: BUFF ( SEID = %llu )", seid);

    if (flags & RULE_BAR_ENABLED) {
      bpf_debug("BAR enabled - delegating to BAR");
      pctx->final_action = FINAL_ACTION_DROP;
      TAIL_CALL_NEXT(ctx, PROG_BAR_APPLY);
      bpf_debug("Tail call to BAR failed");
    } else {
      bpf_debug("BAR not enabled - cannot buffer, dropping");
    }

    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  /* -------------------------------------------------------------- */
  /*  Priority 4: NOTIFY_CP (§8.2.26 bit 3) — informational        */
  /* -------------------------------------------------------------- */
  if (action & PFCP_APPLY_ACTION_NOCP) {
    bpf_debug(
        "Apply Action: NOCP ( SEID = %llu ) - "
        "not supported in XDP",
        seid);
    /*
     * TODO: Trigger notification to control plane via
     * bpf_perf_event_output() or BPF_MAP_TYPE_RINGBUF
     */
  }

  /* -------------------------------------------------------------- */
  /*  Priority 5: DUPLICATE (§8.2.26 bit 4)                         */
  /* -------------------------------------------------------------- */
  if (action & PFCP_APPLY_ACTION_DUPL) {
    bpf_debug(
        "Apply Action: DUPL ( SEID = %llu ) - "
        "not supported in XDP",
        seid);
    /*
     * TODO: Duplicate via bpf_clone_redirect() and apply
     * separate FAR to the clone.
     */
  }

  bpf_debug("No valid Apply Action: action = 0x%02x", action);
  return xdp_stats_record_action(ctx, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
