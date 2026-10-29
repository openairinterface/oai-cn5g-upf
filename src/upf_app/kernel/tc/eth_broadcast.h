/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef __ETH_BROADCAST_H__
#define __ETH_BROADCAST_H__

/* ========================================================================== */
/*                              SYSTEM INCLUDES                               */
/* ========================================================================== */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ========================================================================== */
/*                             PROJECT INCLUDES                               */
/* ========================================================================== */

#include "utils/logger.h"
#include "utils/types.h"
#include "utils/csum.h"
#include "utils/mac_resolution.h"
#include "protocols/gtpu.h"
#include "eth_pdu_types.h"
#include "eth_pdu_maps.h"

/* ========================================================================== */
/*                         BROADCAST DEDUP FAN-OUT CAP                        */
/* ========================================================================== */

/**
 * Maximum number of distinct PDU sessions visited per packet during the
 * bpf_for_each_map_elem() walk of eth_session_mapping_map.
 *
 * Doubles as the size of the per-call dedup array (callback_ctx.pdu_sessions)
 * and as the unroll bound for the linear scan inside broadcast_callback_fn.
 *
 * Kept at a compile-time constant (not the runtime MAX_PDU_SESSIONS .rodata)
 * because clang's `#pragma clang loop unroll(full)` and the BPF stack frame
 * both need a fixed upper bound.
 */
#define MAX_BROADCAST_FANOUT 50

/* ========================================================================== */
/*                            CALLBACK CONTEXT                                */
/* ========================================================================== */

/**
 * @brief Per-packet state threaded through bpf_for_each_map_elem().
 *
 * @field skb           The TC-ingress skb being broadcasted.
 * @field ifindex       The DL egress ifindex, resolved once by the caller.
 * @field qfi           The frame's QFI, saved before the fan-out: clones of
 *                      a session with no known DL QFI keep it. Shares
 *                      ifindex's 8-byte stack slot: the debug build's
 *                      caller + callback stack is at the 512-byte limit.
 * @field pdu_sessions  Dedup array: low 32 bits of the UP SEID of each session
 *                      already visited. UL seeds slot 0 with the source
 *                      session, so it is never cloned to. Keyed on SEID, not
 *                      DL TEID: DL TEIDs are allocated per gNB (TS 29.281
 *                      §3.1) and may repeat across gNBs.
 * @field size          Sessions visited so far, cloned or not. Keep it alone
 *                      in its 8-byte stack slot, or the verifier loses its
 *                      value and the unrolled loop exceeds 1M insns.
 */
struct callback_ctx {
  struct __sk_buff* skb;
  int ifindex;
  __u8 qfi;
  uint32_t pdu_sessions[MAX_BROADCAST_FANOUT];
  int size;
};

/* ========================================================================== */
/*                         CLONE QFI                                          */
/* ========================================================================== */

/**
 * @brief The clones' DL PDU Session Container, or NULL if there is none.
 *
 * Both fan-out paths leave a 4-octet DL container right after the GTP-U
 * header: UL converts the source's UL one, N6 builds it. Octet 2 is
 * PPP | RQI | QFI (TS 38.415 §5.5.2.1).
 */
static __always_inline struct gtpu_extn_pdu_session_container* fanout_container(
    void* data, void* data_end) {
  struct gtpuhdr* gtpuh =
      (struct gtpuhdr*) ((void*) data + sizeof(struct ethhdr) +
                         sizeof(struct iphdr) + sizeof(struct udphdr));
  struct gtpu_extn_pdu_session_container* ext =
      (struct gtpu_extn_pdu_session_container*) (gtpuh + 1);
  if ((void*) (ext + 1) > data_end ||
      gtpuh->next_ext_type != GTP_NEXT_EXT_TYPE ||
      ext->message_length != GTP_EXT_MSG_LEN)
    return NULL;
  return ext;
}

/**
 * @brief Set the QFI of the skb about to be cloned, PPP and RQI 0.
 *
 * The NG-RAN maps a DL G-PDU to a QoS flow by its QFI (TS 38.415 §5.4.1),
 * and DL QoS flow marking comes from the QER of the session's DL PDR
 * (TS 29.244 §5.4.2), not from the frame being copied.
 *
 * @param skb  Invalidates its packet pointers.
 * @param qfi  QFI for the next clone.
 * @return 0 on success or when the frame has no container, else the
 *         bpf_l4_csum_replace() error.
 */
static __always_inline long set_clone_qfi(struct __sk_buff* skb, __u8 qfi) {
  struct gtpu_extn_pdu_session_container* ext =
      fanout_container((void*) (long) skb->data, (void*) (long) skb->data_end);
  if (!ext) return 0;

  __u32 old_ext, new_ext;
  __builtin_memcpy(&old_ext, ext, sizeof(old_ext));
  ext->qfi = qfi & 0x3F;
  __builtin_memcpy(&new_ext, ext, sizeof(new_ext));
  return bpf_l4_csum_replace(
      skb, UDP_CSUM_OFFSET, old_ext, new_ext,
      BPF_F_MARK_MANGLED_0 | sizeof(new_ext));
}

/* ========================================================================== */
/*                         BROADCAST CALLBACK                                 */
/* ========================================================================== */

/**
 * @brief bpf_for_each_map_elem() callback that clones the current skb out to
 *        a single ETH PDU session and records the visited session for dedup.
 *
 * Iteration semantics (kernel docs):
 *   return 0 (RET_SUCCESS) → continue to next map element
 *   return 1 (RET_PASS)    → stop iteration
 *
 * 3GPP Ref: TS 23.501 §5.8.2.5.3 — Ethernet PDU session broadcast
 *   For UL traffic received on N3 over an ETH PDU session, the UPF forwards
 *   to N6 *and* downlinks to every other PDU session (except the source).
 *   Each clone carries its session's DL QFI, or the frame's QFI if that is
 *   unknown (qfi_dl == 0).
 *
 * @param map    The map being iterated (eth_session_mapping_map).
 * @param key    Pointer to the current key (uplink TEID).
 * @param value  Pointer to the current value (struct eth_session_id).
 * @param ctx    Per-call dedup + skb context.
 */
static long broadcast_callback_fn(
    struct bpf_map* map, void* key, void* value, struct callback_ctx* ctx) {
  struct eth_session_id* pdu_session = (struct eth_session_id*) value;

  /* Establishment stores placeholders (teid_dl / gNB IP = 0) until the DL
   * F-TEID is known: never clone to them. */
  if (!pdu_session->teid_dl || !pdu_session->ipv4_address)
    return RET_SUCCESS; /* continue to next */

  struct __sk_buff* skb = (struct __sk_buff*) ctx->skb;
  void* data            = (void*) (long) skb->data;
  void* data_end        = (void*) (long) skb->data_end;

  struct ethhdr* eth_outer = (struct ethhdr*) data;
  if ((void*) (eth_outer + 1) > data_end) {
    bpf_debug("eth_broadcast: invalid outer Ethernet header");
    return RET_SUCCESS; /* continue to next */
  }

  struct iphdr* iph = (struct iphdr*) ((void*) data + sizeof(struct ethhdr));
  if ((void*) (iph + 1) > data_end) {
    bpf_debug("eth_broadcast: invalid IPv4 packet");
    return RET_SUCCESS; /* continue to next */
  }

  struct gtpuhdr* gtpuh =
      (struct gtpuhdr*) ((void*) data + sizeof(struct ethhdr) +
                         sizeof(struct iphdr) + sizeof(struct udphdr));
  if ((void*) gtpuh + sizeof(*gtpuh) > data_end) {
    bpf_debug("eth_broadcast: invalid GTP-U header");
    return RET_SUCCESS; /* continue to next */
  }

  /* TODO: replace #pragma clang loop unroll with bpf_for() (kernel >= 6.3,
   * libbpf >= 1.3) once the project's verifier baseline is bumped. */
  /* UL: the source session is pre-seeded, so it breaks out here
   * (TS 23.501 §5.8.2.5.3). */
  __u32 sid = (__u32) pdu_session->seid;
#pragma clang loop unroll(full)
  for (int v = 0; v < MAX_BROADCAST_FANOUT; v++) {
    /* Only filled slots may match: unused ones are zero. */
    if (v < ctx->size && ctx->pdu_sessions[v] == sid) break;
    if (v == ctx->size) {
      ctx->pdu_sessions[v] = sid;
      ctx->size += 1;

      /* Resolve the outer dst MAC for this session's gNB IP BEFORE
       * touching any header field: ARP first, FIB fallback. The outer src
       * MAC/IP are already the UPF's N3 addresses. */
      __u32 new_daddr   = pdu_session->ipv4_address;
      bool mac_resolved = resolve_mac_via_arp(new_daddr, eth_outer->h_dest);

      if (!mac_resolved) {
        int fib_rc = resolve_mac_via_fib(
            skb, iph, new_daddr, ctx->ifindex, BPF_FIB_LOOKUP_OUTPUT,
            eth_outer->h_dest, NULL, NULL);
        if (fib_rc == BPF_FIB_LKUP_RET_SUCCESS) {
          mac_resolved = true;
        } else {
          bpf_debug(
              "eth_broadcast: no ARP entry and FIB miss (rc=%d) for gNB "
              "%pI4 -- skipping this clone",
              fib_rc, &new_daddr);
        }
      }

      if (!mac_resolved) break;

      bpf_debug(
          "eth_broadcast: cloning to TEID=0x%x dst_mac=%012llx qfi_dl=%u",
          bpf_ntohl(pdu_session->teid_dl), mac_to_u64(eth_outer->h_dest),
          pdu_session->qfi_dl);

      /* Rewrite outer GTP-U TEID + outer dst-IP for this session (dst
       * MAC already written above), then update the IPv4 and UDP
       * checksums (a zero UDP checksum stays zero). The helpers invalidate
       * packet pointers. */
      __u32 old_daddr = iph->daddr;
      __u32 old_teid  = gtpuh->teid;
      __u32 new_teid  = pdu_session->teid_dl;
      gtpuh->teid     = new_teid;
      iph->daddr      = new_daddr;

      /* TEID first: holding the packed old_teid across a helper call
       * overflows the debug build's 512-byte stack. The QFI is the
       * session's DL one, or the frame's if unknown (no QER on its DL
       * PDR); clones share one skb, so this also undoes the last clone's. */
      if (bpf_l4_csum_replace(
              skb, UDP_CSUM_OFFSET, old_teid, new_teid,
              BPF_F_MARK_MANGLED_0 | sizeof(new_teid)) ||
          bpf_l3_csum_replace(
              skb, IP_CSUM_OFFSET, old_daddr, new_daddr, sizeof(new_daddr)) ||
          bpf_l4_csum_replace(
              skb, UDP_CSUM_OFFSET, old_daddr, new_daddr,
              BPF_F_MARK_MANGLED_0 | BPF_F_PSEUDO_HDR | sizeof(new_daddr)) ||
          set_clone_qfi(
              skb, pdu_session->qfi_dl ? pdu_session->qfi_dl : ctx->qfi)) {
        bpf_debug("eth_broadcast: checksum update failed -- stopping fan-out");
        return RET_PASS; /* stop iteration */
      }

      int ret = bpf_clone_redirect(skb, ctx->ifindex, 0);
      if (ret < 0) {
        bpf_debug("eth_broadcast: bpf_clone_redirect failed (ret=%d)", ret);
        return RET_PASS; /* stop iteration */
      }
      break;
    }
  }

  return RET_SUCCESS; /* continue to next */
}

#endif /* __ETH_BROADCAST_H__ */
