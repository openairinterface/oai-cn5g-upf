// clang-format off
#include <types.h>
// clang-format on

#include "xdp_stats_kern.h"
#include <bpf_helpers.h>
#include <endian.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <pfcp/pfcp_far.h>
#include <pfcp/pfcp_pdr.h>
#include <protocols/gtpu.h>
#include <protocols/ip.h>
#include <protocols/tcp.h>
#include <utils/csum.h>
#include <utils/logger.h>
#include <utils/utils.h>
#include <interfaces.h>
#include <string.h>
#include "bpf_endian.h"

#include <linux/pkt_cls.h>
#include <qer_maps.h>

#include <linux/netdevice.h>
#include <linux/pkt_sched.h>

//---------------------------------------------------------------------------------------------------------------
static __always_inline u32 egress_sdf_filter(struct __sk_buff* skb) {
  void* data      = (void*) (long) skb->data;
  void* data_end  = (void*) (long) skb->data_end;
  void* data_meta = (void*) (long) skb->data_meta;

  struct filter_key* sdf = data_meta;
  struct ethhdr* ethh    = data;

  if ((void*) (ethh + 1) > data_end) {
    bpf_debug("Error: Invalid Ethernet header");
    return TC_ACT_SHOT;
  }

  struct iphdr* iph = (struct iphdr*) (ethh + 1);

  if ((void*) (iph + 1) > data_end) {
    bpf_debug("Error: Invalid IPv4 header");
    return TC_ACT_SHOT;
  }

  struct udphdr* udph = (struct udphdr*) (iph + 1);

  if ((void*) (udph + 1) > data_end) {
    bpf_debug("Error: Invalid UDP header");
    return TC_ACT_SHOT;
  }

  struct gtpuhdr* gtpuh = (struct gtpuhdr*) (udph + 1);

  if ((void*) (gtpuh + 1) > data_end) {
    bpf_debug("Error: Invalid GTPU packet");
    return TC_ACT_SHOT;
  }

  struct gtpu_extn_pdu_session_container* gtpu_ext_h =
      (struct gtpu_extn_pdu_session_container*) ((void*) (gtpuh + 1));

  if ((void*) (gtpu_ext_h + 1) > data_end) {
    bpf_debug("Error: Invalid GTPU Extension packet");
    return TC_ACT_SHOT;
  }

  /* Check XDP gave us some data_meta */
  if ((void*) (sdf + 1) > data) {
    bpf_debug("Error: Failed to load metadata from XDP");
    return TC_ACT_SHOT;
  }

  bpf_debug(
      "TC: Received XDP Metadata - dst_ip: %pI4, src_ip: %pI4", &sdf->dst_ip,
      &sdf->dst_ip);
  bpf_debug(
      "TC: Received XDP Metadata - proto: %d, dst_port: %d", &sdf->protocol,
      &sdf->dst_port);

  struct session_qfi* retrieved_value = bpf_map_lookup_elem(&m_sdf_filter, sdf);

  if (retrieved_value) {
    bpf_debug("SDF Found!");
    u8 qfi   = retrieved_value->qfi;
    u64 seid = bpf_ntohs(retrieved_value->seid);

    gtpu_ext_h->qfi = qfi;
    skb->tc_classid =
        (seid << 16) |
        ((seid * 256) + (qfi * 251 % 256));  // ( major << 16 ) | minor
    return TC_ACT_OK;
  }

  u32 key         = 0;
  u8* default_qfi = bpf_map_lookup_elem(&m_default_qfi, &key);

  if (default_qfi) {
    bpf_debug("SDF NOT Found!, Default QFI IS FOUND!");
    gtpu_ext_h->qfi = *default_qfi;
    skb->tc_classid = *default_qfi;
  } else {
    bpf_debug("SDF NOT Found!, Default QFI NOT found, use value 8 as default");
    skb->tc_classid = gtpu_ext_h->qfi;
  }
  return TC_ACT_OK;
}

//---------------------------------------------------------------------------------------------------------------
static __always_inline u32 ipv4_sdf_filter(struct __sk_buff* skb) {
  void* data     = (void*) (long) skb->data;
  void* data_end = (void*) (long) skb->data_end;

  struct ethhdr* ethh = data;

  if ((void*) (ethh + 1) > data_end) {
    bpf_debug("Error: Invalid Ethernet header");
    return TC_ACT_SHOT;
  }

  struct iphdr* iph = (struct iphdr*) (ethh + 1);

  if ((void*) (iph + 1) > data_end) {
    bpf_debug("Error: Invalid IPv4 header");
    return TC_ACT_SHOT;
  }

  if (iph->protocol == IPPROTO_UDP) {
    struct udphdr* udph = (struct udphdr*) (iph + 1);

    if ((void*) (udph + 1) > data_end) {
      bpf_debug("Error: Invalid UDP header");
      return TC_ACT_SHOT;
    }

    if (htons(udph->dest) == GTP_UDP_PORT) {
      bpf_debug("IPv4 SDF Filter: This is a GTP traffic");
      return egress_sdf_filter(skb);
    }
  }

  return TC_ACT_SHOT;
}

//---------------------------------------------------------------------------------------------------------------

SEC("tc/egress")
int tc_filter_traffic(struct __sk_buff* skb) {
  bpf_debug("==========< tc/egress: Filter Traffic >==========");

  void* data     = (void*) (long) skb->data;
  void* data_end = (void*) (long) skb->data_end;

  struct ethhdr* ethh = data;

  if ((void*) (ethh + 1) > data_end) {
    bpf_debug("Error: Invalid Ethernet header");
    return TC_ACT_SHOT;
  }

  u16 eth_type = htons(ethh->h_proto);
  bpf_debug("SDF FILTER: eth_type: 0x%x", eth_type);

  switch (eth_type) {
    case ETH_P_IP: {
      bpf_debug("SDF Filter: This is an IPv4 Packet");
      return ipv4_sdf_filter(skb);
    }
    case ETH_P_IPV6:
    case ETH_P_8021Q:
    case ETH_P_8021AD:
    case ETH_P_ARP:
      return TC_ACT_OK;
    default:
      return TC_ACT_OK;
  }
}

//---------------------------------------------------------------------------------------------------------------

SEC("tc/ingress")
int tc_redirect_traffic(struct __sk_buff* skb) {
  bpf_debug("==========< tc/ingress: Redirect Traffic >==========");

  void* data     = (void*) (long) skb->data;
  void* data_end = (void*) (long) skb->data_end;

  struct filter_key* sdf;
  sdf = (struct filter_key*) skb->data_meta;

  /* Check XDP gave us some data_meta */
  if ((void*) (sdf + 1) > data) {
    bpf_debug("Error: Failed to load metadata from XDP");
    return TC_ACT_SHOT;
  }

  struct ethhdr* ethh = data;

  if ((void*) (ethh + 1) > data_end) {
    bpf_debug("Error: Invalid Ethernet header");
    return TC_ACT_SHOT;
  }

  u16 eth_type = htons(ethh->h_proto);
  bpf_debug("INGRESS: eth_type: 0x%x", eth_type);

  switch (eth_type) {
    case ETH_P_IP: {
      bpf_debug("INGRESS: This is an IPv4 Packet");

      int key = DOWNLINK, *ifindex;
      ifindex = bpf_map_lookup_elem(&m_egress_ifindex, &key);

      if (ifindex) {
        bpf_debug("TC_REDIRECT: Redirecting packet to N3 tc layer");
        return bpf_redirect(*ifindex, 0);
      }

      bpf_debug("TC Packets are not redirected! Drop them");
      return TC_ACT_SHOT;
    }
    case ETH_P_IPV6:
    case ETH_P_8021Q:
    case ETH_P_8021AD:
    case ETH_P_ARP:
      return TC_ACT_OK;
    default:
      return TC_ACT_OK;
  }
}

//---------------------------------------------------------------------------------------------------------------

char _license[] SEC("license") = "GPL";