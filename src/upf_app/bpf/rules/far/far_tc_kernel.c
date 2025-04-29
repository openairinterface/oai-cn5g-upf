#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <protocols/gtpu.h>
#include <utils/logger.h>
#include <utils/utils.h>

#include <linux/pkt_cls.h>

#include <bpf_helpers.h>
#include <bpf_endian.h>

#include <far_broadcast.h>

#include <eth_pdu_session_maps.h>
#include <mac_pdu_session_key.h>

// TODO [ETH-PDU] seperate UL and DL logic
SEC("tc/ingress")
int handle_broadcast(struct __sk_buff* skb) {
  void* data            = (void*) (long) skb->data;
  void* data_end        = (void*) (long) skb->data_end;
  struct ethhdr* eth    = data;
  int action            = TC_ACT_OK;
  struct ethhdr eth_cpy = {};

  if ((void*) (eth + 1) > data_end) {
    // bpf_debug("handle_broadcast: Invalid Ethernet Packet\n");
    goto out;
  }

  struct iphdr* iph = (struct iphdr*) ((void*) data + sizeof(*eth));
  if ((void*) (iph + 1) > data_end) {
    // bpf_debug("handle_broadcast: Invalid IPv4 Packet\n");
    goto out;
  }

  struct udphdr* udph = (struct udphdr*) (iph + 1);
  // Check if the UDP header extends beyond the data end.
  if ((void*) (udph + 1) > data_end) {
    // bpf_debug("handle_broadcast: Invalid UDP packet\n");
    goto out;
  }

  if (bpf_htons(udph->dest) != GTP_UDP_PORT) {
    // bpf_debug("handle_broadcast: This is not a GTP packet\n");
    goto out;
  }

  int key = DOWNLINK, *ifindex;

  ifindex = bpf_map_lookup_elem(&m_egress_ifindex, &key);
  if (!ifindex) {
    bpf_debug("handle_broadcast: failed to find downlink ifindex\n");
    goto out;
  }

  struct gtpuhdr* gtpuh = (struct gtpuhdr*) (udph + 1);
  if ((void*) gtpuh + sizeof(*gtpuh) > data_end) {
    bpf_debug("handle_broadcast: Invalid GTPU packet\n");
    goto out;
  }

  eth =
      (struct
       ethhdr*) ((void*) data + sizeof(struct ethhdr) + GTP_ENCAPSULATED_SIZE);
  if ((void*) (eth + 1) > data_end) {
    bpf_debug("handle_broadcast: Invalid Ethernet Packet\n");
    goto out;
  }
  __builtin_memcpy(&eth_cpy, eth, sizeof(struct ethhdr));

  struct callback_ctx callback_ctx = {
      .skb = skb, .ifindex = ifindex, .size = 0};

  // For UL PDU session
  if (*ifindex == skb->ingress_ifindex) {
    /* The packet from N3 interface and we are sending it back to N3 interface
     * so we need to swap the source and destination MAC address, IPv4 address.
     */
    swap_src_dst_mac(eth);
    swap_src_dst_ipv4(iph);

    // Don't send to source PDU session, add it to the list of PDU sessions
    // that are already broadcasted to.
    callback_ctx.pdu_sessions[0] = gtpuh->teid;
    callback_ctx.size += 1;
  }

  // Broadcast should be sent to all existing PDU session. Use
  // m_next_rule_eth_prog_index map
  long n = bpf_for_each_map_elem(
      &m_next_rule_eth_prog_index, broadcast_callback_fn, &callback_ctx, 0);
  action = TC_ACT_SHOT;

  // For UL also send to N6 after removing the Header
  if (*ifindex == skb->ingress_ifindex) {
    key = UPLINK;

    ifindex = bpf_map_lookup_elem(&m_egress_ifindex, &key);
    if (!ifindex) {
      bpf_debug("handle_broadcast: failed to find uplink ifindex.\n");
      goto out;
    }

    int roomlen = sizeof(struct ethhdr) + GTP_ENCAPSULATED_SIZE;
    if (data + roomlen > data_end) {
      bpf_debug("handle_broadcast: data + roomlen > data_end");
      goto out;
    }

    int ret = bpf_skb_adjust_room(skb, -roomlen, BPF_ADJ_ROOM_MAC, 0);
    if (ret) {
      bpf_debug(
          "handle_broadcast: error bpf_skb_adjust_room, ret = %d, "
          "skb->protocol = %d.\n",
          ret, skb->protocol);
    }

    data     = (void*) (long) skb->data;
    data_end = (void*) (long) skb->data_end;
    eth      = data;
    if ((void*) (eth + 1) > data_end) {
      goto out;
    }
    __builtin_memcpy(eth, &eth_cpy, sizeof(struct ethhdr));

    return bpf_redirect(*ifindex, 0);
  }

out:
  return action;
}

char _license[] SEC("license") = "GPL";