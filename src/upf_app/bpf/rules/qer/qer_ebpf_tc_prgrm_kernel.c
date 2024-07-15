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
#include <far_maps.h>
#include <interfaces.h>
#include <pfcp_session_lookup_maps.h>
#include <string.h>  //Needed for memcpy
#include "bpf_endian.h"

#include <linux/pkt_cls.h>
#include <qer_maps.h>

#include <linux/netdevice.h>
#include <linux/pkt_sched.h>

/*---------------------------------------------------------------------------------------------------------------*/
/**
 * @brief Filter the Uplink traffic
 *
 * @param skb
 * @param udph UDP header
 * @return __inline u32 the TC action taken
 */

static __always_inline u32 uplink_sdf_filter(
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
  key->protocol = iph_inner->protocol;

  switch (protocol) {
    case IPPROTO_UDP: {
      // Extract UDP header
      struct udphdr* udph = (struct udphdr*) (iph_inner + 1);

      if ((void*) (udph + 1) > data_end) {
        bpf_debug("Invalid UDP header");
        return TC_ACT_SHOT;
      }

      key->dst_port = udph->dest;
    }
    case IPPROTO_TCP: {
      // Extract TCP header
      struct tcphdr* tcph = (struct tcphdr*) (iph_inner + 1);

      if ((void*) (tcph + 1) > data_end) {
        bpf_debug("Invalid TCP header");
        return TC_ACT_SHOT;
      }

      key->dst_port = tcph->dest;
    }
    case IPPROTO_ICMP: {
      // TODO: Check how to implement this use case
    }
    default: {
      bpf_debug("Unknown header");
      bpf_debug("Use best effort QoS flow (i.e. default qfi)");
    }
  }

  struct session_id* session = {0};
  session = bpf_map_lookup_elem(&m_session_mapping, &key->src_ip);

  if (session) {
    u32 seid        = session->seid;
    u8 qfi          = gtpu_ext_h->qfi;
    skb->tc_classid = ((u32) qfi << 24) | seid;
    /*
    SHould we make it even more unique than unique value ?
    u32 teid_ul = session->teid_ul;
    u32 teid_dl = session->teid_dl;
    skb->tc_classid = ((u32)qfi << 24) | (seid & teid_ul & teid_dl); //
    */
    return TC_ACT_REDIRECT;
  }
}

/*---------------------------------------------------------------------------------------------------------------*/

static __always_inline u32 downlink_sdf_filter(
    struct __sk_buff* skb, struct ethhdr* ethh, struct iphdr* iph) {
  void* data_end = (void*) (long) skb->data_end;

  struct filter_key* filter = {0};
  u8 protocol               = iph->protocol;
  u32 ip_src                = iph->saddr;
  u32 ip_dst                = iph->daddr;

  filter->src_ip   = ip_src;
  filter->dst_ip   = ip_dst;
  filter->protocol = protocol;

  switch (protocol) {
    case IPPROTO_UDP: {
      // Extract UDP header
      struct udphdr* udph = (struct udphdr*) (iph + 1);

      if ((void*) (udph + 1) > data_end) {
        bpf_debug("Invalid UDP header");
        return TC_ACT_SHOT;
      }

      filter->dst_port = udph->dest;
    }
    case IPPROTO_TCP: {
      // Extract TCP header
      struct tcphdr* tcph = (struct tcphdr*) (iph + 1);

      if ((void*) (tcph + 1) > data_end) {
        bpf_debug("Invalid TCP header");
        return TC_ACT_SHOT;
      }

      filter->dst_port = tcph->dest;
    }
    case IPPROTO_ICMP: {
      // TODO: Check how to implement this use case
    }
    default: {
      bpf_debug("Unknown header");
      bpf_debug("Use best effort QoS flow (i.e. default qfi)");
    }
  }

  // Get QFI value
  e_qfi* qfi = bpf_map_lookup_elem(&m_filter, &filter);
  if (qfi) {
    bpf_debug("\t IP SRC: 0x%x", filter->src_ip);
    bpf_debug("\t IP DST: 0x%x", filter->dst_ip);
    bpf_debug("\t IP PROTO: 0x%x", filter->protocol);
    bpf_debug("\t DST PORT: 0x%x", filter->dst_port);

    struct session_id* session = NULL;

    session = bpf_map_lookup_elem(&m_session_mapping, &ip_dst);

    if (session) {
      u32 seid        = session->seid;
      skb->tc_classid = ((u32) (*qfi) << 24) | seid;
      /*
      SHould we make it even more unique than unique value ?
      u32 teid_ul = session->teid_ul;
      u32 teid_dl = session->teid_dl;
      skb->tc_classid = ((u32)qfi << 24) | (seid & teid_ul & teid_dl); //
      */
      return TC_ACT_REDIRECT;
    }
  }

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
        return uplink_sdf_filter(skb, ethh, udph);
      }
    }
    default: {
      return downlink_sdf_filter(skb, ethh, iph);
    }
  }
}

/*---------------------------------------------------------------------------------------------------------------*/

/**
 * @brief Filter traffic according to ETH_TYPE
 *
 * @param skb
 * @param ethh Ethernet header
 * @return ** __inline TC taken action
 */
static __always_inline u32
sdf_filter(struct __sk_buff* skb, struct ethhdr* ethh) {
  // void *data      = (void *)(long) skb->data;
  void* data_end = (void*) (long) skb->data_end;
  // void *data_meta = (void *)(long) skb->data_meta;
  // struct meta_info *meta = data_meta;

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

SEC("classifier")
int cls_filter(struct __sk_buff* skb) {
  bpf_debug("==========< EGRESS FILTER >==========\n");

  // Extract Ethernet header
  struct ethhdr* ethh = (void*) (long) skb->data;

  if ((void*) (ethh + 1) > (void*) (long) skb->data_end) {
    bpf_debug("Invalid Ethernet header");
    return TC_ACT_SHOT;
  }

  return sdf_filter(skb, ethh);
}

char _license[] SEC("license") = "GPL";
/*---------------------------------------------------------------------------------------------------------------*/