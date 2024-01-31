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
// #include <stdio.h>
// #include <stdlib.h>
// #include <linux/filter.h>
// #include <unistd.h>
// #include <arpa/inet.h>
// #include <net/if.h>
// #include <sys/ioctl.h>
// #include <linux/if_link.h>
#include <qer_maps.h>

#include <linux/netdevice.h>
#include <linux/pkt_sched.h>


// struct qfi_data {
//   __u32 qfi;
// };

// struct bpf_map_def SEC("maps") qfi_map = {
//     .type        = BPF_MAP_TYPE_HASH,
//     .key_size    = sizeof(__u32),
//     .value_size  = sizeof(struct qfi_data),
//     .max_entries = 1024,
// };

// struct qer_data {
//   __u32 qfi;
//   __u64 token_bucket_size;
//   __u64 rate;
// };

// struct bpf_map_def SEC("maps") qer_map = {
//     .type        = BPF_MAP_TYPE_HASH,
//     .key_size    = sizeof(__u32),
//     .value_size  = sizeof(struct qer_data),
//     .max_entries = 1024,
// };

// struct bpf_map_def SEC("maps") token_bucket_map = {
//     .type        = BPF_MAP_TYPE_HASH,
//     .key_size    = sizeof(__u32),
//     .value_size  = sizeof(__u64),
//     .max_entries = 1024,
// };


// SEC("traffic_shape")
// int token_bucket_filter(struct __sk_buff* skb) {
//   // Retrieve the QFI from the packet data
//   __u32 qfi = (__u32) skb->cb[0];

//   // Retrieve QER data based on QFI
//   struct qer_data* qer = bpf_map_lookup_elem(&qer_map, &qfi);
//   if (!qer) {
//     // QER not configured for the QFI, allow the packet
//     return TC_ACT_OK;
//   }
 
//   // Retrieve token bucket for the QFI
//   __u64* tokens = bpf_map_lookup_elem(&token_bucket_map, &qfi);
//   if (!tokens) {
//     // Token bucket not initialized, allow the packet
//     return TC_ACT_OK;
//   }

//   // Calculate tokens based on rate
//   __u64 elapsed_time = bpf_ktime_get_ns() / 1000 - qer->token_bucket_size;
//   __u64 tokens_per_sec =
//       qer->rate / 1000000;  // Convert rate from bps to tokens per microsecond
//   __u64 elapsed_tokens = elapsed_time * tokens_per_sec;

//   // Refill token bucket
//   *tokens = *tokens + elapsed_tokens;
//   if (*tokens > qer->token_bucket_size) {
//     *tokens = qer->token_bucket_size;
//   }

//   // Consume tokens for the packet
//   __u64 packet_size = (__u64) skb->len;
//   if (packet_size > *tokens) {
//     // Insufficient tokens, drop the packet
//     return TC_ACT_SHOT;
//   }

//   *tokens = *tokens - packet_size;

//   return TC_ACT_OK;
// }

// SEC("traffic_shape")
// int token_bucket_filter(struct __sk_buff* skb) {
//   // Extract Ethernet header
//   struct ethhdr* eth = bpf_hdr_pointer(skb);

//   // Filter IP packets
//   if (eth->h_proto != __constant_htons(ETH_P_IP)) return TC_ACT_OK;

//   // Extract IP header
//   struct iphdr* ip = (struct iphdr*) (eth + 1);

//   // Filter TCP packets
//   if (ip->protocol != IPPROTO_TCP) return TC_ACT_OK;

//   // Extract TCP header
//   struct tcphdr* tcp = (struct tcphdr*) (ip + 1);

//   // Extract QFI from the IP header
//   __u8 qfi = (__u8) (ip->tos & 0x3F);

//   // Retrieve QER data based on QFI
//   struct qer_data* qer = bpf_map_lookup_elem(&qer_map, &qfi);
//   if (!qer) {
//     // QER not configured for the QFI, allow the packet
//     return TC_ACT_OK;
//   }

//   // Retrieve token bucket for the QFI
//   __u64* tokens = bpf_map_lookup_elem(&token_bucket_map, &qfi);
//   if (!tokens) {
//     // Token bucket not initialized, allow the packet
//     return TC_ACT_OK;
//   }

//   // Calculate tokens based on rate
//   __u64 elapsed_time = bpf_ktime_get_ns() / 1000 - qer->token_bucket_size;
//   __u64 new_tokens   = elapsed_time * qer->rate / 1000000;
//   if (new_tokens > qer->token_bucket_size) {
//     new_tokens = qer->token_bucket_size;
//   }
//   qer->token_bucket_size = new_tokens;

//   if (*tokens >= skb->len) {
//     // Sufficient tokens available, consume tokens and allow the packet
//     *tokens -= skb->len;
//     return TC_ACT_OK;
//   } else {
//     // Insufficient tokens, drop the packet
//     return TC_ACT_SHOT;
//   }
// }


/*****************************************************************************************************************/
/**
 * @brief Filter the Uplink traffic 
 * 
 * @param skb 
 * @param udph UDP header
 * @return __inline u32 the TC action taken
 */

static __always_inline u32 uplink_sdf_filter(struct __sk_buff *skb, struct ethhdr* ethh, struct udphdr* udph) {
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
  
  u8 protocol   = iph_inner->protocol;
  
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

  if (session){
    u32 seid = session->seid;
    u8 qfi = gtpu_ext_h->qfi;
    skb->tc_classid = ((u32)qfi << 24) | seid;
    /*
    SHould we make it even more unique than unique value ?
    u32 teid_ul = session->teid_ul;
    u32 teid_dl = session->teid_dl;
    skb->tc_classid = ((u32)qfi << 24) | (seid & teid_ul & teid_dl); //   
    */
    return TC_ACT_REDIRECT;
  }

}

/*****************************************************************************************************************/

static __always_inline u32 downlink_sdf_filter(struct __sk_buff *skb, struct ethhdr* ethh, struct iphdr* iph) {
  void* data_end = (void*) (long) skb->data_end;

  struct filter_key* filter = {0};
  u8 protocol = iph->protocol;
  u32 ip_src  = iph->saddr;
  u32 ip_dst  = iph->daddr;
  
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
  if (qfi){
    bpf_debug("\t IP SRC: 0x%x", filter->src_ip);
    bpf_debug("\t IP DST: 0x%x", filter->dst_ip);
    bpf_debug("\t IP PROTO: 0x%x", filter->protocol);
    bpf_debug("\t DST PORT: 0x%x", filter->dst_port);

    struct session_id* session = NULL;
    
    session = bpf_map_lookup_elem(&m_session_mapping, &ip_dst);
    
    if (session){
      u32 seid = session->seid;
      skb->tc_classid = ((u32)(*qfi) << 24) | seid;
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
  
/*****************************************************************************************************************/
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

static __always_inline u32 ipv4_sdf_filter(struct __sk_buff *skb, struct ethhdr* ethh, struct iphdr* iph) {
  void* data_end = (void*) (long) skb->data_end;
  u8 protocol = iph->protocol;

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

/*****************************************************************************************************************/

/**
 * @brief Filter traffic according to ETH_TYPE
 * 
 * @param skb 
 * @param ethh Ethernet header
 * @return ** __inline TC taken action
 */
static __always_inline u32 sdf_filter(struct __sk_buff *skb, struct ethhdr* ethh){
  //void *data      = (void *)(long) skb->data;
	void *data_end  = (void *)(long) skb->data_end;
	//void *data_meta = (void *)(long) skb->data_meta;
	//struct meta_info *meta = data_meta;

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

/*****************************************************************************************************************/

/**
 * @brief sections to be ran as eBPF tc code
 * 
 */

// SEC("ingress_filter")
// int ingress_filter_entry_point(struct __sk_buff *skb) {
// bpf_debug("==========< INGRESS FILTER >==========\n");  
// Extract Ethernet header
// struct ethhdr* ethh = bpf_hdr_pointer(skb);

// if ((void*) (ethh + 1) > (void*) (long) skb->data_end) {
//    bpf_debug("Invalid Ethernet header");
//    return TC_ACT_SHOT;
//  }
//   return sdf_filter(skb, ethh);
// }

/*
To forward packets from the Traffic Control (tc) ingress to tc egress, 
you need to create an appropriate setup for traffic shaping and queuing. 
This involves setting up both the ingress and egress qdiscs 
along with filters to direct the traffic accordingly. 
Here's a basic example using tc commands:

1. Create an Ingress Queue:
bash
  tc qdisc add dev <ingress_interface> handle ffff: ingress
  

2. Create an Egress Queue:

  tc qdisc add dev <egress_interface> root handle 1: htb default 10
  tc class add dev <egress_interface> parent 1: classid 1:1 htb rate <egress_rate>

Replace <egress_interface> with the name of your egress interface 
(e.g., eth0) and <egress_rate> with the desired rate for outgoing traffic.

3. Filter Ingress Traffic and Redirect to Egress:
bash
  tc filter add dev <ingress_interface> parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev <egress_interface>

This filter rule matches all incoming IP traffic on the <ingress_interface> 
and redirects it to the egress interface <egress_interface>.

Adjust the interface names, rates, and other parameters based on your 
network configuration. The above commands provide a basic example, 
and you may need to customize them for your specific requirements.

Keep in mind that this is a simple example, and real-world scenarios might 
involve more complex configurations, especially if you need to apply specific 
traffic shaping policies or prioritize different types of traffic. 
Additionally, the effectiveness of traffic shaping depends on the traffic 
patterns and the specific use case.

TO DO IT WITHIN THE CODE:
=========================

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>

struct bpf_map_def SEC("maps") qdisc_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 1,
};

SEC("classifier")
int handle_ingress(struct __sk_buff *skb) {
    int key = 0;
    int *qdisc_handle;

    qdisc_handle = bpf_map_lookup_elem(&qdisc_map, &key);
    if (!qdisc_handle) {
        return TC_ACT_OK;
    }

    bpf_redirect(*qdisc_handle, 0);
    return TC_ACT_SHOT;
}

*/


SEC("egress_filter")
int egress_filter_entry_point(struct __sk_buff *skb) {
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
/*****************************************************************************************************************/