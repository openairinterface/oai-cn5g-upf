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
#include "protocols/gtpu.h"
#include "eth_pdu_types.h"
#include "eth_pdu_maps.h"
#include "arp_maps.h"

#ifndef AF_INET
#define AF_INET 2
#endif

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
 * @field ifindex       Pointer to the egress ifindex (kept indirected so the
 *                      caller can resolve it once outside the loop).
 * @field pdu_sessions  Dedup array: TEIDs already cloned to during this call.
 * @field size          Current population of pdu_sessions[].
 */
struct callback_ctx {
  struct __sk_buff* skb;
  int* ifindex;
  uint32_t pdu_sessions[MAX_BROADCAST_FANOUT];
  int size;
};

/* ========================================================================== */
/*                    FIB LOOKUP SCRATCH (STACK RELIEF)                       */
/* ========================================================================== */

/**
 * @brief Per-CPU scratch slot for the ARP-miss FIB fallback lookup.
 *
 * struct bpf_fib_lookup is 64 bytes. broadcast_callback_fn() is invoked as
 * a bpf_for_each_map_elem() callback, so its stack frame is combined with
 * handle_broadcast()'s frame for the kernel verifier's stack-depth check
 * (512-byte total budget across the call chain) -- keeping this struct on
 * the callback's own stack pushed that combined total over the limit.
 *
 * BPF_MAP_TYPE_PERCPU_ARRAY gives each CPU its own copy, so this is safe
 * with no locking: a single CPU never has two BPF program instances live
 * in this struct concurrently.
 */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct bpf_fib_lookup);
} fib_lookup_scratch_map SEC(".maps");

/* ========================================================================== */
/*                         BROADCAST CALLBACK                                 */
/* ========================================================================== */

/**
 * @brief bpf_for_each_map_elem() callback that clones the current skb out to
 *        a single ETH PDU session and records the visited TEID for dedup.
 *
 * Iteration semantics (kernel docs):
 *   return 0 (RET_SUCCESS) → continue to next map element
 *   return 1 (RET_PASS)    → stop iteration
 *
 * 3GPP Ref: TS 23.501 §5.8.2.5.3 — Ethernet PDU session broadcast
 *   For UL traffic received on N3 over an ETH PDU session, the UPF forwards
 *   to N6 *and* downlinks to every other PDU session (except the source).
 *
 * @param map    The map being iterated (eth_session_mapping_map).
 * @param key    Pointer to the current key (uplink TEID).
 * @param value  Pointer to the current value (struct eth_session_id).
 * @param ctx    Per-call dedup + skb context.
 */
static long broadcast_callback_fn(
    struct bpf_map* map, void* key, void* value, struct callback_ctx* ctx) {
  struct eth_session_id* pdu_session = (struct eth_session_id*) value;

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
      (struct
       gtpuhdr*) ((void*) data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));
  if ((void*) gtpuh + sizeof(*gtpuh) > data_end) {
    bpf_debug("eth_broadcast: invalid GTP-U header");
    return RET_SUCCESS; /* continue to next */
  }

  /* TODO: replace #pragma clang loop unroll with bpf_for() (kernel >= 6.3,
   * libbpf >= 1.3) once the project's verifier baseline is bumped. */
#pragma clang loop unroll(full)
  for (int v = 0; v < MAX_BROADCAST_FANOUT; v++) {
    if (ctx->pdu_sessions[v] == pdu_session->teid_dl) break;
    if (v == ctx->size) {
      ctx->pdu_sessions[v] = pdu_session->teid_dl;
      ctx->size += 1;

      /* Resolve the outer dst MAC for this session's gNB IP BEFORE
       * touching any header field. ARP is checked first; FIB is a fallback
       * for parity with update_mac_address() / gtpu_decap_ipv4() elsewhere
       * in the codebase. */
      __u32 old_daddr   = iph->daddr;
      __u32 new_daddr   = pdu_session->ipv4_address;
      bool mac_resolved = false;

      struct arp_entry* arp = bpf_map_lookup_elem(&arp_table_map, &new_daddr);
      if (arp) {
        __builtin_memcpy(eth_outer->h_dest, arp->mac_address, ETH_ALEN);
        mac_resolved = true;
      } else {
        /* ARP miss -- fall back to a FIB lookup from an egress
         * perspective.
         *
         * The lookup struct lives in fib_lookup_scratch_map, not on the
         * stack. It is a per-CPU slot reused across calls, so it must be
         * cleared before use. */
        __u32 scratch_key = 0;
        struct bpf_fib_lookup* fib =
            bpf_map_lookup_elem(&fib_lookup_scratch_map, &scratch_key);
        if (!fib) {
          bpf_debug("eth_broadcast: fib_lookup_scratch_map lookup failed");
          break;
        }
        __builtin_memset(fib, 0, sizeof(*fib));
        fib->family      = AF_INET;
        fib->tos         = iph->tos;
        fib->l4_protocol = iph->protocol;
        fib->tot_len     = bpf_ntohs(iph->tot_len);
        fib->ipv4_src    = iph->saddr;
        fib->ipv4_dst    = new_daddr;
        fib->ifindex     = *ctx->ifindex;

        int fib_rc =
            bpf_fib_lookup(skb, fib, sizeof(*fib), BPF_FIB_LOOKUP_OUTPUT);
        if (fib_rc == BPF_FIB_LKUP_RET_SUCCESS) {
          __builtin_memcpy(eth_outer->h_dest, fib->dmac, ETH_ALEN);
          mac_resolved = true;
        } else {
          bpf_debug(
              "eth_broadcast: no ARP entry and FIB miss (rc=%d) for gNB "
              "%pI4 -- skipping this clone",
              fib_rc, &new_daddr);
        }
      }

      if (!mac_resolved) break;

      /* Rewrite outer GTP-U TEID + outer dst-IP for this session (dst
       * MAC already written above), fix up the IPv4 header checksum for
       * the daddr change, then clone the packet out the egress (N3)
       * interface. */
      gtpuh->teid = pdu_session->teid_dl;
      iph->daddr  = new_daddr;

      bpf_l3_csum_replace(
          skb, IP_CSUM_OFFSET, old_daddr, new_daddr, sizeof(new_daddr));

      int ret = bpf_clone_redirect(skb, *ctx->ifindex, 0);
      if (ret < 0) {
        bpf_debug("eth_broadcast: bpf_clone_redirect failed (ret=%d)", ret);
        return RET_PASS; /* stop iteration */
      }
      bpf_debug(
          "eth_broadcast: cloned to PDU session TEID=0x%x dst_mac=%pM",
          bpf_ntohl(pdu_session->teid_dl), eth_outer->h_dest);
      break;
    }
  }

  return RET_SUCCESS; /* continue to next */
}

#endif /* __ETH_BROADCAST_H__ */
