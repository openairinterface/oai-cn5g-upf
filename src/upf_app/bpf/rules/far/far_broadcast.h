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

#include <eth_pdu_session_maps.h>
#include <mac_pdu_session_key.h>
#include <next_prog_rule_key.h>
#include <pfcp_session_lookup_maps.h>

#define MAX_PDU_SESSIONS 50
struct callback_ctx {
    struct __sk_buff *skb;
    int *ifindex;
    uint32_t pdu_sessions[MAX_PDU_SESSIONS];
    int size;
};

static long broadcast_callback_fn(struct bpf_map *map, void *key, void *value,
                struct callback_ctx *ctx)
{
    
    struct next_rule_eth_prog_index_value *pdu_session = (struct next_rule_eth_prog_index_value*) value;

    struct __sk_buff *skb = (struct __sk_buff *) ctx->skb;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long) skb->data_end;

    struct iphdr* iph = (struct iphdr*) ((void*) data + sizeof(struct ethhdr));
    if ((void*) (iph + 1) > data_end) {
        bpf_printk("broadcast_callback_fn: Invalid IPv4 Packet");
        return 0;
    }

    struct gtpuhdr* gtpuh = (struct gtpuhdr*) ((void*) data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));
    // struct gtpuhdr* gtpuh = (struct gtpuhdr*) ((void*) data + ctx->gtpuh_offset);
    if ((void*) gtpuh + sizeof(*gtpuh) > data_end) {
        bpf_printk("broadcast_callback_fn: Invalid GTPU packet");
        return 0;
    }

    /**
     * Broadcast support (23.501 Section 5.8.2.5.3)
     * 
     * for UL traffic received by UPF over a PDU session on a N3/N9 interface, 
     * the UPF should forward the traffic to the N6 interface and downlink to 
     * every PDU session (except toward the one of the incoming traffic)
     * */
    int v;
    bpf_for(v, 0, MAX_PDU_SESSIONS) {
        if (ctx->pdu_sessions[v] == bpf_htonl(pdu_session->teid_dl))
            break;
        if (v == ctx->size) {
            ctx->pdu_sessions[v] = bpf_htonl(pdu_session->teid_dl);
            ctx->size += 1;
            gtpuh->teid = bpf_htonl(pdu_session->teid_dl);
            iph->daddr = pdu_session->ipv4_address;
            int ret = bpf_clone_redirect(skb, *ctx->ifindex, 0);
            if (ret < 0) {
                bpf_printk("broadcast_callback_fn: failed to redirect clone\n");
                return 1;
            }
            break;
        }
    }

    return 0;
}

#endif  // __FAR_BROADCAST_H__