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
      bpf_debug("==========< egress_sdf_filter >==========\n");
  void *data_end = (void *)(unsigned long long)skb->data_end;
  void *data = (void *)(unsigned long long)skb->data;

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

  struct ethhdr* ethh_new = (void*) (data + GTP_ENCAPSULATED_SIZE);

  if ((void*) ethh_new + sizeof(*ethh_new) > data_end) {
    bpf_debug("egress_sdf_filter: Invalid Ethernet packet");
    return TC_ACT_SHOT;
  }

  struct iphdr* iph_inner = (void*) (ethh_new + 1);
  if ((void*) (iph_inner + 1) > data_end) {
    bpf_debug("egress_sdf_filter: Invalid Inner IP packet");
    return TC_ACT_SHOT;
  }
  

  // if ((void*) iph_inner + sizeof(*iph_inner) > data_end) {
  //   bpf_debug("egress_sdf_filter: Invalid Inner IP packet");
  //   return TC_ACT_SHOT;
  // }

  // bpf_debug("egress_sdf_filter: passing inner ip test");

  /**
   * 1. ETH
   * 2. Inner Ip
   * 3. UDP
   * 4. GTPU
   * 5. GTPU ext
   * 6. IP
   * 7. UDP
   * 
   */
  // struct iphdr* iph_inner = (void*) (ethh + 1);

  // if ((void*) iph_inner + sizeof(*iph_inner) > data_end) {
  //   bpf_debug("egress_sdf_filter: Invalid Inner IP packet");
  //   return TC_ACT_SHOT;
  // }

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
    bpf_debug("classid %d", classid);
    skb->tc_classid = classid;
    return TC_ACT_OK;
  }

  // default value qfi = 5 (NON-GBR QoS Flow)
  skb->tc_classid = gtpu_ext_h->qfi;
  bpf_debug("skb->tc_classid %d or ", skb->tc_classid, bpf_htons(skb->tc_classid));
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
ipv4_sdf_filter_old(struct __sk_buff* skb, struct ethhdr* ethh, struct iphdr* iph) {
  bpf_debug("==========< ipv4_sdf_filter >==========\n");
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
  bpf_debug("==========< sdf_filter >==========\n");
  void* data_end = (void*) (long) skb->data_end;
  void *data = (void *)(long) skb->data;

  int payload_len = (data_end - data) - sizeof(struct ethhdr);

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

      // check if skb is non-linear, it if is and pull in non-linear data
      if (bpf_ntohs(iph->tot_len) > payload_len) {
        bpf_debug("sdf_filter: tc buffer is non-linear");
        // if (bpf_skb_pull_data(skb, bpf_ntohs(iph->tot_len) + sizeof(struct ethhdr)) < 0)
        //     return TC_ACT_UNSPEC;
      }

      return ipv4_sdf_filter_old(skb, ethh, iph);
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

/***** Adapted from commit: c4b6ef3ea238652926a003b630eb5cc7fcb3db12 *****/
//---------------------------------------------------------------------------------------------------------------
static __always_inline u32 egress_sdf_classifier(struct __sk_buff* skb) {
  void* data      = (void*) (long) skb->data;
  void* data_end  = (void*) (long) skb->data_end;
  void* data_meta = (void*) (long) skb->data_meta;

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
  struct filter_key* filter = data_meta;
  if ((void*) (filter + 1) > data) {
    bpf_debug("Error: Failed to load metadata from XDP");
    return TC_ACT_SHOT;
  }

  bpf_debug(
      "TC: Received XDP Metadata - dst_ip: %pI4, src_ip: %pI4", &filter->dst_ip,
      &filter->src_ip);
  bpf_debug(
    "TC: Received XDP Metadata - dst_ip: %d, src_ip: %d", filter->dst_ip,
    filter->src_ip);
  bpf_debug(
      "TC: Received XDP Metadata - protocol: 0x%x, dst_port: %d", filter->protocol,
      filter->dst_port);
  bpf_debug(
    "TC: Received XDP Metadata - TOS: %d", filter->tos);


  struct session_qfi* retrieved_value =
      bpf_map_lookup_elem(&m_sdf_filter, filter);

  if (retrieved_value) {
    u8 qfi   = retrieved_value->qfi;
    u64 seid = retrieved_value->seid;
    bpf_debug("TC: Retrieved QFI: %d", qfi);
    bpf_debug("TC: Retrieved SEID: %d", seid);

    gtpu_ext_h->qfi = qfi;
    skb->tc_classid = GET_TC_CLASSID(seid, qfi);
    bpf_debug("TC: classid %d", skb->tc_classid);
    return TC_ACT_OK;
  }

  // TODO [QOS] assign default QFI

  bpf_debug("No default QFI found. Droping packet");
  return TC_ACT_SHOT;
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

/***** End of adaptation *****/

/*---------------------------------------------------------------------------------------------------------------*/

SEC("tc/egress")
int tc_filter_traffic(struct __sk_buff* skb) {
  bpf_debug("==========< TC Egress >==========\n");

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

  // bpf_debug("TC Retrieves a Marker metadata value: %d", skb->mark);

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

  struct iphdr* iph = (struct iphdr*) (ethh + 1);

  if ((void*) (iph + 1) > (void*) (long) skb->data_end) {
    bpf_debug("Invalid IPv4 header");
    return TC_ACT_SHOT;
  }

  bpf_debug("SDF FILTER: IP SRC: %pI4, IP DST: %pI4", &iph->saddr, &iph->daddr);

  u16 l3_protocol = htons(ethh->h_proto);
  bpf_debug("SDF FILTER: l3_protocol: 0x%x", l3_protocol);

  // return sdf_filter(skb, ethh);
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

// /*---------------------------------------------------------------------------------------------------------------*/

SEC("tc/ingress")
int tc_redirect_traffic(struct __sk_buff* skb) {
  bpf_debug("==========< TC Ingress >==========\n");

  /***** Adapted from commit: c4b6ef3ea238652926a003b630eb5cc7fcb3db12 *****/
  void* data     = (void*) (long) skb->data;
  void* data_end = (void*) (long) skb->data_end;

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

      // If it is an IPv4 packet, we expect the filter key to be present in the metadata
      struct filter_key* filter;
      filter = (struct filter_key*) skb->data_meta;

      /* Check XDP gave us some data_meta */
      if ((void*) (filter + 1) > data) {
        bpf_debug("Error: Failed to load metadata from XDP");
        return TC_ACT_SHOT;
      }

      struct iphdr* iph = (struct iphdr*) (ethh + 1);

      if ((void*) (iph + 1) > (void*) (long) skb->data_end) {
        bpf_debug("Invalid IPv4 header");
        return TC_ACT_SHOT;
      }

      bpf_debug("INGRESS: IP SRC: %pI4, IP DST: %pI4", &iph->saddr, &iph->daddr);

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

  /***** End of adaptation *****/

}

char _license[] SEC("license") = "GPL";
/*---------------------------------------------------------------------------------------------------------------*/
