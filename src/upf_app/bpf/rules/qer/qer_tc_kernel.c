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
//#include <far_maps.h>
#include <interfaces.h>
//#include <pfcp_session_lookup_maps.h>
#include <string.h>  //Needed for memcpy
#include "bpf_endian.h"

#include <linux/pkt_cls.h>
#include <qer_maps.h>

#include <linux/netdevice.h>
#include <linux/pkt_sched.h>

#define MARK_VALUE 0x12345678  // Marker value to match
#define OFFSET 0               // Example offset where marker is stored
#define TARGET_INTF 644
/*---------------------------------------------------------------------------------------------------------------*/
/**
 * @brief Filter the Uplink traffic
 *
 * @param skb
 * @param udph UDP header
 * @return __inline u32 the TC action taken
 */

static __always_inline u32 egress_sdf_filter(
    struct __sk_buff* skb, struct ethhdr* ethh, struct udphdr* udph) {
  void* data_end = (void*) (long) skb->data_end;

  struct gtpuhdr* gtpuh = (struct gtpuhdr*) (udph + 1);

  // Check if the GTP header extends beyond the data end.
  if ((void*) gtpuh + sizeof(*gtpuh) > data_end) {
    bpf_debug("Invalid GTPU packet");
    return TC_ACT_SHOT;
  }

  struct gtpu_extn_pdu_session_container* gtpu_ext_h = (void*) (gtpuh + 1);

  // Check if the GTP extension header extends beyond the data end.
  if ((void*) gtpu_ext_h + sizeof(*gtpu_ext_h) > data_end) {
    bpf_debug("Invalid GTPU Extension packet");
    return TC_ACT_SHOT;
  }

  struct iphdr* iph_inner = (void*) (ethh + 1);

  if ((void*) iph_inner + sizeof(*iph_inner) > data_end) {
    bpf_debug("Invalid Inner IP packet");
    return TC_ACT_SHOT;
  }

  struct filter_key* key = {0};

  u8 protocol = iph_inner->protocol;

  key->src_ip   = iph_inner->saddr;
  key->dst_ip   = iph_inner->daddr;
  key->protocol = protocol;

  switch (protocol) {
    case IPPROTO_UDP: {
      // Extract UDP header
      struct udphdr* udph = (struct udphdr*) (iph_inner + 1);

      if ((void*) (udph + 1) > data_end) {
        bpf_debug("Invalid UDP header");
        return TC_ACT_SHOT;
      }

      key->dst_port = udph->dest;
      break;
    }
    case IPPROTO_TCP: {
      // Extract TCP header
      struct tcphdr* tcph = (struct tcphdr*) (iph_inner + 1);

      if ((void*) (tcph + 1) > data_end) {
        bpf_debug("Invalid TCP header");
        return TC_ACT_SHOT;
      }

      key->dst_port = tcph->dest;
      break;
    }
    default: {
      bpf_debug("Unknown header");
      bpf_debug("Use best effort QoS flow (i.e. default qfi)");
      key->dst_port = 65535;
    }
  }

  struct session_qfi* retrieved_value =
      bpf_map_lookup_elem(&m_sdf_filter, &key);

  if (retrieved_value) {
    u8 qfi   = retrieved_value->qfi;
    u64 seid = bpf_ntohs(retrieved_value->seid);

    gtpu_ext_h->qfi = qfi;
    u32 classid =
        (seid << 16) |
        ((seid * 256) + (qfi * 251 % 256));  // ( major << 16 ) | minor
    skb->tc_classid = classid;
    return TC_ACT_OK;
  }

  // default value qfi = 5 (NON-GBR QoS Flow)
  skb->tc_classid = gtpu_ext_h->qfi;
  return TC_ACT_OK;
}

/*---------------------------------------------------------------------------------------------------------------*/
/**
 * IP SECTION.
 */

/**
 * @brief Filter IPv4 header.
 *
 * @param skb The user accessible metadata for tc packet hook.
 * @param iph The IP header.
 * @return u32 The TC action.
 */

static __always_inline u32
ipv4_sdf_filter(struct __sk_buff* skb, struct ethhdr* ethh, struct iphdr* iph) {
  void* data_end = (void*) (long) skb->data_end;
  u8 protocol    = iph->protocol;

  switch (protocol) {
    case IPPROTO_UDP: {
      // Extract UDP header
      struct udphdr* udph = (struct udphdr*) (iph + 1);

      if ((void*) (udph + 1) > data_end) {
        bpf_debug("Invalid UDP header");
        return TC_ACT_SHOT;
      }

      if (htons(udph->dest) == GTP_UDP_PORT) {
        bpf_printk("This is a GTP traffic");
        return egress_sdf_filter(skb, ethh, udph);
      }
    }
    default: {
      return XDP_DROP;
    }
  }
}

/*---------------------------------------------------------------------------------------------------------------*/
struct meta_info {
  __u32 mark;
} __attribute__((aligned(4)));

/**
 * @brief Filter traffic according to ETH_TYPE
 *
 * @param skb
 * @param ethh Ethernet header
 * @return ** __inline TC taken action
 */
static __always_inline u32
sdf_filter(struct __sk_buff* skb, struct ethhdr* ethh) {
  void* data_end = (void*) (long) skb->data_end;

  u16 eth_type = htons(ethh->h_proto);
  bpf_debug("Debug: eth_type:0x%x", eth_type);

  switch (eth_type) {
    case ETH_P_IP: {
      // Extract IP header
      struct iphdr* iph = (struct iphdr*) (ethh + 1);

      if ((void*) (iph + 1) > data_end) {
        bpf_debug("Invalid IPv4 header");
        return TC_ACT_SHOT;
      }

      return ipv4_sdf_filter(skb, ethh, iph);
    }
    case ETH_P_IPV6: {
      // TODO: Check if traitment is needed here
      return TC_ACT_OK;
    }
    case ETH_P_8021Q: {
      // TODO: Check if traitment is needed here
      return TC_ACT_OK;
    }
    case ETH_P_8021AD: {
      // TODO: Check if traitment is needed here
      return TC_ACT_OK;
    }
    case ETH_P_ARP: {
      // TODO: Check if traitment is needed here
      return TC_ACT_OK;
    }
    default: {
      // TODO: Check if traitment is needed here
      return TC_ACT_OK;
    }
  }
}

/*---------------------------------------------------------------------------------------------------------------*/

SEC("tc")
int tc_filter_traffic(struct __sk_buff* skb) {
  bpf_debug("==========< QER Rules >==========\n");

  // void *data      = (void *)(long)skb->data;
  // void *data_meta = (void *)(long)skb->data_meta;
  // struct meta_info *meta = data_meta;

  // /* Check SKB gave us some data_meta */
  // if ((void *)(meta + 1) > data) {
  // 	skb->mark = 41;
  // 	 bpf_debug("No Meta_data found! Drop the packet");
  // 	return TC_ACT_SHOT;
  // }

  // /* Hint: See func tc_cls_act_is_valid_access() for BPF_WRITE access */
  // skb->mark = meta->mark; /* Transfer XDP-mark to SKB-mark */

  bpf_debug("TC Retrieves a Marker metadata value: %d", skb->mark);

  // Check if the marker matches
  // if (skb->mark == htonl(MARK_VALUE)) {
  //   bpf_debug("TC_REDIRECT: Redirecting packet to N3 tc layer");
  //   return bpf_redirect_map(&m_redirect_interfaces, DOWNLINK, 0);
  // }

  // Extract Ethernet header
  struct ethhdr* ethh = (void*) (long) skb->data;

  if ((void*) (ethh + 1) > (void*) (long) skb->data_end) {
    bpf_debug("Invalid Ethernet header");
    return TC_ACT_SHOT;
  }

  return sdf_filter(skb, ethh);
}

// /*---------------------------------------------------------------------------------------------------------------*/

SEC("tc")
int tc_redirect_traffic(struct __sk_buff* skb) {
  int key = DOWNLINK, *ifindex;

  // return bpf_redirect_map(&m_redirect_interfaces, DOWNLINK, 0);

  /* Lookup what ifindex to redirect packets to */
  ifindex = bpf_map_lookup_elem(&m_egress_ifindex, &key);
  if (ifindex) {
    bpf_debug("TC_REDIRECT: Redirecting packet to N3 tc layer");
    return bpf_redirect(*ifindex, 0);
  }
  bpf_debug("TC Packets not redirected! Drop them");
  return TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";
/*---------------------------------------------------------------------------------------------------------------*/
