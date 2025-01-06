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
    bpf_printk("callback_fn: pdu_session->teid = %d", pdu_session->teid);

    // // If teid (pdu session) is the same skip
    // if (pdu_session->teid == gtpuh->teid) {
    //     bpf_printk("callback_fn: same tied, skipping");
    //     return 0;
    // }

    /**
     * Broadcast support (23.501 Section 5.8.2.5.3)
     * 
     * for UL traffic received by UPF over a PDU session on a N3/N9 interface, 
     * the UPF should forward the traffic to the N6 interface and downlink to 
     * every PDU session (except toward the one of the incoming traffic)
     * */ 
    int v;
    bpf_for(v, 0, MAX_PDU_SESSIONS) {
        bpf_printk("X = %d, gtpuh->teid = %d, pdu_session->teid = %d, bpf_htonl = %d", v, gtpuh->teid, pdu_session->teid, bpf_htonl(pdu_session->teid));
        if (ctx->pdu_sessions[v] == bpf_htonl(pdu_session->teid))
            break;
        if (v == ctx->size) {
            ctx->pdu_sessions[v] = bpf_htonl(pdu_session->teid);
            ctx->size += 1;
            gtpuh->teid = bpf_htonl(pdu_session->teid);
            iph->daddr = pdu_session->ipv4_address;
            bpf_printk("handle_broadcast SRC IP: %pI4, DST IP: %pI4", &iph->saddr, &iph->daddr);
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

SEC("tc/egress")
int handle_n3_outgoing_broadcast(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    int action = TC_ACT_OK;
    int payload_len = (data_end - data);
    bpf_printk("handle_n3_outgoing_broadcast: payload_len %d", payload_len);

    if ((void*) (eth + 1) > data_end)
    {
        bpf_printk("handle_outgoing_broadcast: Invalid Ethernet Packet");
        action = TC_ACT_OK;
        goto out;
    }

    bpf_printk("handle_n3_outgoing_broadcast: eth->h_proto = %d", eth->h_proto);

out:
    return action;
}

SEC("tc/egress")
int handle_outgoing_broadcast(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    int action = TC_ACT_OK;
    int payload_len = (data_end - data);
    bpf_printk("handle_outgoing_broadcast: payload_len %d", payload_len);

    if ((void*) (eth + 1) > data_end)
    {
        bpf_printk("handle_outgoing_broadcast: Invalid Ethernet Packet");
        action = TC_ACT_OK;
        goto out;
    }

    struct iphdr* iph = (struct iphdr*) ((void*) data + sizeof(*eth));
    if ((void*) (iph + 1) > data_end) {
        bpf_printk("Invalid IPv4 Packet");
        action = TC_ACT_OK;
        goto out;
    }

    bpf_printk("handle_outgoing_broadcast SRC IP: %pI4, DST IP: %pI4 LEN: %d", &iph->saddr, &iph->daddr, bpf_ntohs(iph->tot_len));

    struct ethhdr* ethh_new = data + GTP_ENCAPSULATED_SIZE + sizeof(struct ethhdr);
    if ((void*) (ethh_new + 1) > data_end)
    {
        bpf_printk("handle_outgoing_broadcast: Invalid Ethernet Packet");
        action = TC_ACT_OK;
        goto out;
    }
    bpf_printk("handle_outgoing_broadcast SRC MAC: %pM, DST MAC: %pM", &ethh_new->h_source, &ethh_new->h_dest);
    bpf_printk("handle_outgoing_broadcast 1 SRC MAC: %pM, DST MAC: %pM", ethh_new->h_source, ethh_new->h_dest);

    bpf_printk("handle_outgoing_broadcast 2 SRC MAC: %pMR, DST MAC: %pMR", &ethh_new->h_source, &ethh_new->h_dest);
    bpf_printk("handle_outgoing_broadcast 3 SRC MAC: %pMR, DST MAC: %pMR", ethh_new->h_source, ethh_new->h_dest);

    struct ethhdr eth_cpy = {};
    __builtin_memcpy(&eth_cpy, ethh_new, sizeof(struct ethhdr));

    int roomlen = sizeof(struct ethhdr) + GTP_ENCAPSULATED_SIZE;
    if (data + roomlen > data_end) {
        bpf_printk("handle_outgoing_broadcast: data + roomlen > data_end");
        return TC_ACT_SHOT;
    }

    int ret = bpf_skb_adjust_room(skb, -roomlen, BPF_ADJ_ROOM_MAC, 0);
    if (ret) {
        bpf_printk("handle_outgoing_broadcast: error bpf_skb_adjust_room, ret = %d, skb->protocol = %d.\n", ret, skb->protocol);
    }

    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    eth = data;
    if ((void*) (eth + 1) > data_end)
    {
        bpf_printk("handle_outgoing_broadcast: Invalid Ethernet Packet");
        action = TC_ACT_OK;
        goto out;
    }
    __builtin_memcpy(eth, &eth_cpy, sizeof(struct ethhdr));

    bpf_printk("handle_outgoing_broadcast: eth->h_proto = %d", eth->h_proto);

out:
    return action;
}

SEC("tc/ingress")
int handle_broadcast(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    int action = TC_ACT_OK;
    int payload_len = (data_end - data);
    bpf_printk("handle_broadcast: payload_len %d", payload_len);

    if ((void*) (eth + 1) > data_end)
    {
        bpf_printk("Invalid Ethernet Packet");
        action = TC_ACT_OK;
        goto out;
    }
    swap_src_dst_mac(eth);
    bpf_printk("handle_broadcast: eth->h_proto = %d", eth->h_proto);

    struct iphdr* iph = (struct iphdr*) ((void*) data + sizeof(*eth));
    if ((void*) (iph + 1) > data_end) {
        bpf_printk("Invalid IPv4 Packet");
        action = TC_ACT_OK;
        goto out;
    }
    swap_src_dst_ipv4(iph);
    bpf_printk("handle_broadcast SRC IP: %pI4, DST IP: %pI4 LEN: %d", &iph->saddr, &iph->daddr, bpf_ntohs(iph->tot_len));

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
    uint32_t teid = gtpuh->teid;

    payload_len = (data_end - data) - sizeof(struct ethhdr);
    if (bpf_ntohs(iph->tot_len) > payload_len) {
        bpf_printk("handle_broadcast: bpf_ntohs(iph->tot_len) = %d, payload_len = %d", bpf_ntohs(iph->tot_len), payload_len);
        if (bpf_skb_pull_data(skb, bpf_ntohs(iph->tot_len) + sizeof(struct ethhdr)) < 0) {
            bpf_printk("handle_broadcast: bpf_skb_pull_data");
            return TC_ACT_UNSPEC;
        }
    }

    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;

    struct ethhdr* ethh_new = data + GTP_ENCAPSULATED_SIZE;

    struct iphdr* iph_inner = (void*) (ethh_new + 1);

    if ((void*) iph_inner + sizeof(*iph_inner) > data_end) {
        bpf_printk("Invalid Inner IP packet");
        action = TC_ACT_OK;
        goto out;
    }

    int key = DOWNLINK, *ifindex;
    
    ifindex = bpf_map_lookup_elem(&m_egress_ifindex, &key);
    if (!ifindex) {
        action = TC_ACT_OK;
        goto out;
    }
    bpf_printk("far_tc_kernel: ifindex = %d, skb->ingress_ifindex = %d ", *ifindex, skb->ingress_ifindex);

    // If this is on N6, send to all downlink, but not to uplink

    /**
     * for DL traffic received by UPF on a N6 Network Instance the UPF should forward the traffic to every DL PDU Session
     */
    
    // Means if this is UL, another packet should be sent to UPLINK
    // If this is DL then need to all PDU session, hence initial teid should be invalid so that for loop goes


    // Initial TIED is zero, if the array doesn't have zero on [0] then 
    


    if (!(iph_inner->version == 4 || iph_inner->version == 6)) { // Not IP packet
        bpf_printk("Not an IP packet, attempting ETH PDU");
        eth = (void*) (ethh_new + 1);

        if (eth->h_dest[0] != 0xff || eth->h_dest[1] != 0xff ||
            eth->h_dest[2] != 0xff || eth->h_dest[3] != 0xff ||
            eth->h_dest[4] != 0xff || eth->h_dest[5] != 0xff) {
            bpf_printk("Not a broadcast packet\n");
            return TC_ACT_OK; // Drop broadcast packets (or take other action)
        }
        
        bpf_printk("far_tc_kernel: ifindex ---> %d", *ifindex);
        // long (*cb_p)(struct bpf_map *, const void *, int *, void *) = &callback_fn;
        struct callback_ctx callback_ctx = { .skb = skb, .ifindex = ifindex,
        .inner_eth = eth, .size = 0 };
        
        // For UL PDU session (except toward the one of the incoming traffic)
        if (*ifindex == skb->ingress_ifindex) {
            callback_ctx.pdu_sessions[0] = teid;
            callback_ctx.size += 1;
        }

        long n = bpf_for_each_map_elem(&m_mac_pdu_session, callback_fn, &callback_ctx, 0);
        bpf_printk("far_tc_kernel: transversed ---> %lu", n);
        action = TC_ACT_OK;
    }

    // For UL also send to N6 after removing the Header
    if (*ifindex == skb->ingress_ifindex) {
        // int roomlen = GTP_ENCAPSULATED_SIZE + sizeof(struct ethhdr);
        // int ret = bpf_skb_adjust_room(skb, -roomlen, BPF_ADJ_ROOM_MAC, 0);
        // if (ret) {
        //     bpf_printk("far_tc_kernel: error reducing skb adjust room.\n");
        //     return TC_ACT_SHOT;
        // }
        key = UPLINK;
    
        ifindex = bpf_map_lookup_elem(&m_egress_ifindex, &key);
        if (!ifindex) {
            bpf_printk("far_tc_kernel: failed to find downlink ifindex.\n");
            action = TC_ACT_OK;
            goto out;
        }
        return bpf_redirect(*ifindex, 0);
    }

out:     
    bpf_printk("far_tc_kernel: returning with final action\n");
    return TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";