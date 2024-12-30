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

#define MAX_PDU_SESSIONS 50
struct callback_ctx {
    struct __sk_buff *skb;
    struct ethhdr *inner_eth;
    struct gtpuhdr* gtpuh;
    int *ifindex;
    uint32_t pdu_sessions[MAX_PDU_SESSIONS];
    int size;
};

static void swap_src_dst_mac(struct ethhdr *eth)
{
        __u8 h_tmp[ETH_ALEN];

        __builtin_memcpy(h_tmp, eth->h_source, ETH_ALEN);
        __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
        __builtin_memcpy(eth->h_dest, h_tmp, ETH_ALEN);
}

/*
 * Swaps destination and source IPv4 addresses inside an IPv4 header
 */
static void swap_src_dst_ipv4(struct iphdr *iphdr)
{
        __be32 tmp = iphdr->saddr;

        iphdr->saddr = iphdr->daddr;
        iphdr->daddr = tmp;
}

static long callback_fn(struct bpf_map *map, void *key, void *value,
                struct callback_ctx *ctx)
{
    struct mac_pdu_session_value *pdu_session = (struct mac_pdu_session_value*) value;
    // struct gtpuhdr* gtpuh = (struct gtpuhdr*) data->gtpuh;

    // // Check if the GTP header extends beyond the data end.
    // if ((void*) gtpuh + sizeof(*gtpuh) > data->skb->data_end) {
    //     bpf_printk("Invalid GTPU packet");
    //     return 1;
    // }
    struct __sk_buff *skb = (struct __sk_buff *) ctx->skb;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long) skb->data_end;
    struct ethhdr* eth = (struct ethhdr*) data;

    if ((void*) (eth + 1) > data_end)
    {
        bpf_printk("callback_fn: Invalid Ethernet Packet");
        return 0;
    }

    struct iphdr* iph = (struct iphdr*) ((void*) data + sizeof(*eth));
    if ((void*) (iph + 1) > data_end) {
        bpf_printk("callback_fn: Invalid IPv4 Packet");
        return 0;
    }

    struct udphdr* udph = (struct udphdr*) (iph + 1);
    // Check if the UDP header extends beyond the data end.
    if ((void*) (udph + 1) > data_end) {
        bpf_printk("callback_fn: Invalid UDP packet");
        return 0;
    }

    if (bpf_htons(udph->dest) != GTP_UDP_PORT) {
        bpf_printk("callback_fn: This is not a GTP packet");
        return 0;
    }

    struct gtpuhdr* gtpuh = (struct gtpuhdr*) (udph + 1);
    if ((void*) gtpuh + sizeof(*gtpuh) > data_end) {
        bpf_printk("callback_fn: Invalid GTPU packet");
        return 0;
    }

    struct ethhdr* ethh_new = data + GTP_ENCAPSULATED_SIZE + sizeof(struct ethhdr);
    if ((void*) (ethh_new + 1) > data_end)
    {
        bpf_printk("callback_fn: Invalid inner ETH packet");
        return 0;
    }

    // // If teid (pdu session) is the same skip
    if (pdu_session->teid == gtpuh->teid) {
        bpf_printk("callback_fn: same tied, skipping");
        return 1;
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
        bpf_printk("X = %d", v);
        if (ctx->pdu_sessions[v] == pdu_session->teid)
            break;
        if (v == ctx->size) {
            ctx->pdu_sessions[v] = pdu_session->teid;
            ctx->size += 1;
            gtpuh->teid = pdu_session->teid;
            int ret = bpf_clone_redirect(skb, *ctx->ifindex, 0);
            if (ret < 0) {
                bpf_printk("far_tc_kernel: failed to redirect clone\n");
                return 1;
            }
            break;
        }
    }

    bpf_printk("far_tc_kernel: successful redirect clone on ifindex -> %d, ctx->size -> %d\n", *ctx->ifindex, ctx->size);
    return 0;
}

SEC("tc/ingress")
int handle_broadcast(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    int action = TC_ACT_OK;
    

    if ((void*) (eth + 1) > data_end)
    {
        bpf_printk("Invalid Ethernet Packet");
        action = TC_ACT_OK;
        goto out;
    }
    swap_src_dst_mac(eth);

    struct iphdr* iph = (struct iphdr*) ((void*) data + sizeof(*eth));
    if ((void*) (iph + 1) > data_end) {
        bpf_printk("Invalid IPv4 Packet");
        action = TC_ACT_OK;
        goto out;
    }
    swap_src_dst_ipv4(iph);

    struct udphdr* udph = (struct udphdr*) (iph + 1);
    // Check if the UDP header extends beyond the data end.
    if ((void*) (udph + 1) > data_end) {
        bpf_printk("Invalid UDP packet");
        action = TC_ACT_OK;
        goto out;
    }

    if (bpf_htons(udph->dest) != GTP_UDP_PORT) {
        bpf_printk("This is not a GTP packet");
        action = TC_ACT_OK;
        goto out;
    }

    struct gtpuhdr* gtpuh = (struct gtpuhdr*) (udph + 1);
    if ((void*) gtpuh + sizeof(*gtpuh) > data_end) {
        bpf_printk("Invalid GTPU packet");
        action = TC_ACT_OK;
        goto out;
    }

    struct ethhdr* ethh_new = data + GTP_ENCAPSULATED_SIZE;

    struct iphdr* iph_inner = (void*) (ethh_new + 1);

    if ((void*) iph_inner + sizeof(*iph_inner) > data_end) {
        bpf_printk("Invalid Inner IP packet");
        action = TC_ACT_OK;
        goto out;
    }

    int key = DOWNLINK, *ifindex;

    

    if (!(iph_inner->version == 4 || iph_inner->version == 6)) { // Not IP packet
        bpf_printk("Not an IP packet, attempting ETH PDU");
        eth = (void*) (ethh_new + 1);

        if (eth->h_dest[0] != 0xff || eth->h_dest[1] != 0xff ||
            eth->h_dest[2] != 0xff || eth->h_dest[3] != 0xff ||
            eth->h_dest[4] != 0xff || eth->h_dest[5] != 0xff) {
            bpf_printk("Not a broadcast packet\n");
            return TC_ACT_OK; // Drop broadcast packets (or take other action)
        }
        ifindex = bpf_map_lookup_elem(&m_egress_ifindex, &key);
        if (ifindex) {
            bpf_printk("far_tc_kernel: ifindex ---> %d", *ifindex);
            // long (*cb_p)(struct bpf_map *, const void *, int *, void *) = &callback_fn;
            struct callback_ctx callback_ctx = { .skb = skb, .ifindex = ifindex,
            .inner_eth = eth, .gtpuh = gtpuh, .size = 0 };
            long n = bpf_for_each_map_elem(&m_mac_pdu_session, callback_fn, &callback_ctx, 0);
            bpf_printk("far_tc_kernel: transversed ---> %lu", n);
            action = TC_ACT_OK;
            goto out;
        } else {
            bpf_printk("far_tc_kernel: ifindex not defined");
            action = TC_ACT_OK;
            goto out;
        }
    }

out:     
    bpf_printk("far_tc_kernel: returning with final action\n");
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";