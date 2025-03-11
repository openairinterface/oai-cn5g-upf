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

#define GET_TC_CLASSID(seid, qfi)                                              \
  (((seid) << 16) | (((seid) *256) + ((qfi) *251 % 256)))

static __always_inline u32 match_sdf_filter_ipv4(
    const struct metadata_filter* filter, const struct sdf_filter* sdf) {
  u8 packet_protocol  = filter->protocol;
  u16 packet_src_port = filter->src_port;
  u16 packet_dst_port = filter->dst_port;
  u32 packet_src_ip   = bpf_htonl(filter->src_ip);
  u32 packet_dst_ip   = bpf_htonl(filter->dst_ip);

  u32 sdf_src_ip   = bpf_htonl(sdf->src_addr.ip);
  u32 sdf_dst_ip   = bpf_htonl(sdf->dst_addr.ip);
  u32 sdf_src_mask = bpf_htonl(sdf->src_addr.mask);
  u32 sdf_dst_mask = bpf_htonl(sdf->dst_addr.mask);

  bpf_debug("SDF: filter protocol: %u", sdf->protocol);
  bpf_debug(
      "SDF: filter source ip: %pI4, destination ip: %pI4", &sdf_src_ip,
      &sdf_dst_ip);
  bpf_debug(
      "SDF: filter source ip mask: %pI4, destination ip mask: %pI4",
      &sdf_src_mask, &sdf_dst_mask);
  bpf_debug(
      "SDF: filter source port lower bound: %u, source port upper bound: %u",
      sdf->src_port.lower_bound, sdf->src_port.upper_bound);
  bpf_debug(
      "SDF: filter destination port lower bound: %u, destination port upper "
      "bound: %u",
      sdf->dst_port.lower_bound, sdf->dst_port.upper_bound);

  bpf_debug("SDF: packet protocol: %u", packet_protocol);
  bpf_debug(
      "SDF: packet source ip: %pI4, destination ip: %pI4", &packet_src_ip,
      &packet_dst_ip);
  bpf_debug(
      "SDF: packet source port: %u, destination port: %u", packet_src_port,
      packet_dst_port);

  // TODO: Start with the hit and not miss
  /*
   * TODO:
   * 1. Start with the hit and not miss
   * 2. Check if an enum is really needed to redifine protocol:
   * switch (ip_protocol) {
         case IPPROTO_ICMP:
           return 0;
         case IPPROTO_TCP:
           return 2;
         case IPPROTO_UDP:
           return 3;
         default:
           return 1;
     }
 */
  if ((sdf->protocol == 1 || sdf->protocol == packet_protocol) &&
      ((packet_src_ip & sdf_src_mask) == sdf_src_ip) &&
      ((packet_dst_ip & sdf_dst_mask) == sdf_dst_ip) &&
      (packet_src_port >= sdf->src_port.lower_bound &&
       packet_src_port <= sdf->src_port.upper_bound) &&
      (packet_dst_port >= sdf->dst_port.lower_bound &&
       packet_dst_port <= sdf->dst_port.upper_bound)) {
    return 1;
  }

  bpf_debug("Packet Metadata and SDF are matching");
  return 0;
}

//---------------------------------------------------------------------------------------------------------------
static __always_inline u32 egress_sdf_classifier(struct __sk_buff* skb) {
  void* data      = (void*) (long) skb->data;
  void* data_end  = (void*) (long) skb->data_end;
  void* data_meta = (void*) (long) skb->data_meta;

  struct metadata_filter* filter = data_meta;
  struct ethhdr* ethh            = data;

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
  if ((void*) (filter + 1) > data) {
    bpf_debug("Error: Failed to load metadata from XDP");
    return TC_ACT_SHOT;
  }

  bpf_debug(
      "TC: Received XDP Metadata - dst_ip: %pI4, src_ip: %pI4", &filter->dst_ip,
      &filter->src_ip);
  bpf_debug(
      "TC: Received XDP Metadata - proto: %d, dst_port: %d", &filter->protocol,
      &filter->dst_port);

  for (u8 key = 0; key < MAX_SDF_FITLER_ENTRIES; key++) {
    struct sdf_filter* sdf = bpf_map_lookup_elem(&m_sdf_filter, &key);
    if (sdf && match_sdf_filter_ipv4(&filter, &sdf)) {
      bpf_debug("An SDF Filter matched to the packet");
      u8 qfi   = sdf->session.qfi;
      u64 seid = bpf_ntohs(sdf->session.seid);

      gtpu_ext_h->qfi = qfi;
      skb->tc_classid = GET_TC_CLASSID(seid, qfi);
      // (seid << 16) |
      // ((seid * 256) + (qfi * 251 % 256));  // ( major << 16 ) | minor
      return TC_ACT_OK;
    }
  }

  bpf_debug(
      "No SDF Filter matched. Defining the best effort QoS Flow for Internet "
      "PDU Session");
  u8 key          = 0;
  u8* default_qfi = bpf_map_lookup_elem(&m_default_qfi, &key);

  if (default_qfi) {
    bpf_debug("Default QFI %d", *default_qfi);
    gtpu_ext_h->qfi = *default_qfi;
    skb->tc_classid = *default_qfi;
  } else {
    bpf_debug("No default QFI found. Droping packet");
    return TC_ACT_SHOT;
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
      return egress_sdf_classifier(skb);
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

  u16 l3_protocol = htons(ethh->h_proto);
  bpf_debug("SDF FILTER: l3_protocol: 0x%x", l3_protocol);

  switch (l3_protocol) {
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

  struct metadata_filter* filter;
  filter = (struct metadata_filter*) skb->data_meta;

  /* Check XDP gave us some data_meta */
  if ((void*) (filter + 1) > data) {
    bpf_debug("Error: Failed to load metadata from XDP");
    return TC_ACT_SHOT;
  }

  struct ethhdr* ethh = data;

  if ((void*) (ethh + 1) > data_end) {
    bpf_debug("Error: Invalid Ethernet header");
    return TC_ACT_SHOT;
  }

  u16 l3_protocol = htons(ethh->h_proto);
  bpf_debug("INGRESS: l3_protocol: 0x%x", l3_protocol);

  switch (l3_protocol) {
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