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

//---------------------------------------------------------------------------------------------------------------
static __always_inline u32 egress_sdf_filter(
    struct __sk_buff* skb) {
  void *data      = (void *)(long)skb->data;
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

  struct udphdr* udph = (struct udphdr*) (iph + 1);
  if ((void*) (udph + 1) > data_end) {
    bpf_debug("Error: Invalid UDP header");
    return TC_ACT_SHOT;
  }

  struct gtpuhdr* gtpuh = (struct gtpuhdr*) (udph + 1);
  // if ((void*) (gtpuh + 1) > data_end) {
  //   bpf_debug("Error: Invalid GTPU packet");
  //   return TC_ACT_SHOT;
  // }

  struct gtpu_extn_pdu_session_container* gtpu_ext_h = (void*) (gtpuh + 1);
  // if ((void*) (gtpu_ext_h + 1) > data_end) {
  //   bpf_debug("Error: Invalid GTPU Extension packet");
  //   return TC_ACT_SHOT;
  // }

  struct iphdr* iph_inner = (void*) (gtpu_ext_h + 1);

  // if ((void*) (iph_inner+ 1) > data_end) {
  //   bpf_debug("Error: Invalid Inner IP packet");
  //   return TC_ACT_SHOT;
  // }

  struct filter_key* key = {0};

  u8 protocol = iph_inner->protocol;
 
  //bpf_debug("Create Key for SDF Filter Map"); 

  key->src_ip   = iph_inner->saddr;
  key->dst_ip   = iph_inner->daddr;
  key->protocol = protocol;
   
  switch (protocol) {
    case IPPROTO_UDP: {
      // Extract UDP header
      struct udphdr* udph = (struct udphdr*) (iph_inner + 1);

      if ((void*) (udph + 1) > data_end) {
        bpf_debug("Error: Invalid UDP header");
        return TC_ACT_SHOT;
      }

      key->dst_port = udph->dest;
      break;
    }
    case IPPROTO_TCP: {
      // Extract TCP header
      struct tcphdr* tcph = (struct tcphdr*) (iph_inner + 1);

      if ((void*) (tcph + 1) > data_end) {
        bpf_debug("Error: Invalid TCP header");
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

//---------------------------------------------------------------------------------------------------------------
static __always_inline u32
ipv4_sdf_filter(struct __sk_buff* skb) {
  void *data      = (void *)(long)skb->data;
  void *data_end  = (void *)(long)skb->data_end;
  
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

  u8 protocol    = iph->protocol;

  switch (protocol) {
    case IPPROTO_UDP: {
      struct udphdr* udph = (struct udphdr*) (iph + 1);

      if ((void*) (udph + 1) > data_end) {
        bpf_debug("Error: Invalid UDP header");
        return TC_ACT_SHOT;
      }

      if (htons(udph->dest) == GTP_UDP_PORT) {
        bpf_printk("IPv4 SDF Filter: This is a GTP traffic");
        return egress_sdf_filter(skb);
      }
    }
    default: {
      return TC_ACT_SHOT;
    }
  }
}


//---------------------------------------------------------------------------------------------------------------

SEC("tc/egress")
int tc_filter_traffic(struct __sk_buff* skb) {
  bpf_debug("==========< tc/egress: Filter Traffic >==========\n");

  void *data      = (void *)(long)skb->data;
  void *data_end  = (void *)(long)skb->data_end;

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
    case ETH_P_IPV6: {
      // TODO: Check if traitment is needed here
      bpf_debug("SDF Filter: This is an IPv6 Packet");
      return TC_ACT_OK;
    }
    case ETH_P_8021Q: {
      // TODO: Check if traitment is needed here
      bpf_debug("SDF Filter: This is a VLAN Packet");
      return TC_ACT_OK;
    }
    case ETH_P_8021AD: {
      // TODO: Check if traitment is needed here
      bpf_debug("SDF Filter: This is a VLAN Packet");
      return TC_ACT_OK;
    }
    case ETH_P_ARP: {
      // TODO: Check if traitment is needed here
      bpf_debug("SDF Filter: This is an ARP Packet");
      return TC_ACT_OK;
    }
    default: {
      // TODO: Check if traitment is needed here
      bpf_debug("SDF Filter: Packet Type not Known");
      return TC_ACT_OK;
    }
  }
}

//---------------------------------------------------------------------------------------------------------------

SEC("tc/ingress")
int tc_redirect_traffic(struct __sk_buff* skb) {
  bpf_debug("==========< tc/ingress: Redirect Traffic >==========\n");
  int key = DOWNLINK, *ifindex;

  ifindex = bpf_map_lookup_elem(&m_egress_ifindex, &key);
  
  if (ifindex) {
    bpf_debug("TC_REDIRECT: Redirecting packet to N3 tc layer");
    return bpf_redirect(*ifindex, 0);
  }
  
  bpf_debug("TC Packets not redirected! Drop them");
  return TC_ACT_SHOT;
}

//---------------------------------------------------------------------------------------------------------------

char _license[] SEC("license") = "GPL";