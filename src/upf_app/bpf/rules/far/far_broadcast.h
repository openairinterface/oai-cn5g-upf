#ifndef __FAR_BROADCAST_H__
#define __FAR_BROADCAST_H__

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <protocols/gtpu.h>

#include <linux/pkt_cls.h>

#include <bpf_helpers.h>
#include <bpf_endian.h>

#include <utils/logger.h>
#include <utils/types.h>
#include <eth_pdu_session_maps.h>
#include <mac_pdu_session_key.h>
#include <pfcp_session_eth__lookup_maps.h>

#define MAX_PDU_SESSIONS 50
struct callback_ctx {
  struct __sk_buff* skb;
  int* ifindex;
  uint32_t pdu_sessions[MAX_PDU_SESSIONS];
  int size;
};

static long broadcast_callback_fn(
    struct bpf_map* map, void* key, void* value, struct callback_ctx* ctx) {
  struct eth__session_id* pdu_session = (struct eth__session_id*) value;

  struct __sk_buff* skb = (struct __sk_buff*) ctx->skb;
  void* data            = (void*) (long) skb->data;
  void* data_end        = (void*) (long) skb->data_end;

  struct iphdr* iph = (struct iphdr*) ((void*) data + sizeof(struct ethhdr));
  if ((void*) (iph + 1) > data_end) {
    bpf_debug("broadcast_callback_fn: Invalid IPv4 Packet");
    return SUCCESS;  // continue to next
  }

  struct gtpuhdr* gtpuh =
      (struct
       gtpuhdr*) ((void*) data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));
  // struct gtpuhdr* gtpuh = (struct gtpuhdr*) ((void*) data +
  // ctx->gtpuh_offset);
  if ((void*) gtpuh + sizeof(*gtpuh) > data_end) {
    bpf_debug("broadcast_callback_fn: Invalid GTPU packet");
    return SUCCESS;  // continue to next
  }

/**
 * Broadcast support (23.501 Section 5.8.2.5.3)
 *
 * for UL traffic received by UPF over a PDU session on a N3/N9 interface,
 * the UPF should forward the traffic to the N6 interface and downlink to
 * every PDU session (except toward the one of the incoming traffic)
 * */

/* Within this callback function pdu_sessions keeps track of the PDU sessions
 * (teid) that are already broadcasted. The size of the array is limited to
 * MAX_PDU_SESSIONS. Return 0 if the PDU session is already in the array, will
 * cause the calling MAP iterator (bpf_for_each_map_elem) to move to the next
 * element (PDU session) in the map. When the map iterator reaches the end, it
 * will stop calling this callback function.
 * */
// TODO: use bpf_for instead of #pragma clang loop unroll. Requires Kernel
// >= 6.3
#pragma clang loop unroll(full)
  for (int v = 0; v < MAX_PDU_SESSIONS; v++) {
    if (ctx->pdu_sessions[v] == pdu_session->teid_dl) break;
    if (v == ctx->size) {
      ctx->pdu_sessions[v] = pdu_session->teid_dl;
      ctx->size += 1;
      gtpuh->teid = pdu_session->teid_dl;
      iph->daddr  = pdu_session->ipv4_address;
      int ret     = bpf_clone_redirect(skb, *ctx->ifindex, 0);
      if (ret < 0) {
        bpf_debug("broadcast_callback_fn: failed to redirect clone\n");
        return PASS;  // skip the rest of the PDU sessions and return to caller
      }
      bpf_debug(
          "broadcast_callback_fn: Redirected packet to PDU session TEID %llx",
          pdu_session->teid_dl);
      break;
    }
  }

  return SUCCESS;  // continue to next
}

#endif  // __FAR_BROADCAST_H__