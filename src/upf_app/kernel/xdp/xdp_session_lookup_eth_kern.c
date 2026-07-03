/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#define KBUILD_MODNAME session_lookup_eth

/* ========================================================================== */
/*                              SYSTEM INCLUDES                               */
/* ========================================================================== */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>

/* ========================================================================== */
/*                             PROJECT INCLUDES                               */
/* ========================================================================== */

#include "linux/custom_types.h"
#include "utils/logger.h"

/* Maps and definitions */
#include "eth_pdu_maps.h"
#include "tail_call_dispatcher.h"
#include "stats_maps.h"
#include "stats_types.h"

/* ========================================================================== */
/*                     ETH SESSION LOOKUP ENTRY POINT                         */
/* ========================================================================== */

SEC("xdp")
int session_lookup_eth(struct xdp_md* ctx) {
  bpf_debug("=== ETH Session Lookup (TS 23.501 §5.6.10.3) ===");

  struct packet_context* pctx = GET_PACKET_CONTEXT();

  if (!pctx) {
    bpf_debug("ETH Lookup: Failed to get packet context");
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  /* ---------------------------------------------------------- */
  /*  TEID -> Session mapping                                   */
  /*                                                            */
  /*  ETH PDU sessions are identified by TEID (not UE IP).      */
  /*  The eth_session_mapping_map is populated by control plane  */
  /*  during PFCP Session Establishment (TS 29.244 §7.2.2).     */
  /* ---------------------------------------------------------- */
  __u32 teid = pctx->pkt_teid;

  struct eth_session_id* session =
      bpf_map_lookup_elem(&eth_session_mapping_map, &teid);

  if (!session) {
    bpf_debug("ETH Lookup: No session for TEID=0x%x", bpf_ntohl(teid));
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  __u64 seid    = session->seid;
  __u32 teid_ul = bpf_htonl(session->teid_ul);
  __u32 teid_dl = bpf_htonl(session->teid_dl);

  bpf_debug(
      "ETH Lookup: Session found (SEID=%llu, "
      "teid_ul=0x%x, teid_dl=0x%x)",
      seid, teid_ul, teid_dl);

  /* ---------------------------------------------------------- */
  /*  MAC Address Learning                                      */
  /*                                                            */
  /*  Record inner source MAC -> (DL TEID, gNB IP) so that      */
  /*  downlink traffic destined to this MAC can be properly      */
  /*  encapsulated. This is the ETH PDU equivalent of the IP    */
  /*  session_by_ue_ip map for IP PDU sessions.                 */
  /*                                                            */
  /*  Using BPF_ANY to update on every UL packet ensures the    */
  /*  latest gNB association is always current (handles          */
  /*  handover scenarios where the same UE MAC appears from     */
  /*  a different gNB).                                         */
  /* ---------------------------------------------------------- */
  struct mac_pdu_session_value pdu_session_val;

  pdu_session_val.teid         = session->teid_dl;
  pdu_session_val.ipv4_address = pctx->gnb_ipv4;

  bpf_map_update_elem(
      &mac_pdu_session_map, pctx->inner_eth_src, &pdu_session_val, BPF_ANY);

  bpf_debug(
      "ETH Lookup: MAC learned src=%02x:%02x:%02x -> ", pctx->inner_eth_src[0],
      pctx->inner_eth_src[1], pctx->inner_eth_src[2]);
  bpf_debug(
      "                                   DL TEID=0x%x",
      bpf_htonl(session->teid_dl));

  /* ---------------------------------------------------------- */
  /*  Populate session context in pctx                          */
  /* ---------------------------------------------------------- */
  pctx->seid    = seid;
  pctx->teid_ul = teid_ul;
  pctx->teid_dl = teid_dl;

  /*
   * Load per-session rule enable flags (same map as IP PDU).
   * Controls which downstream programs are active for this session.
   */
  __u32* flags = bpf_map_lookup_elem(&session_rules_enabled_map, &seid);

  pctx->rules_enabled = flags ? *flags : 0;

  bpf_debug("ETH Lookup: rules_enabled=0x%x", pctx->rules_enabled);

  /* ---------------------------------------------------------- */
  /*  Tail call: PDR Match (shared with IP PDU sessions)        */
  /*                                                            */
  /*  PDR match reads pctx->session_type to branch into the     */
  /*  ETH-specific PDR matching logic (TEID + QFI, no SDF).     */
  /* ---------------------------------------------------------- */
  TAIL_CALL_NEXT(ctx, PROG_PDR_MATCH);

  bpf_debug("ETH Lookup: Tail call to PDR_MATCH failed");
  return xdp_stats_record_action(ctx, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
