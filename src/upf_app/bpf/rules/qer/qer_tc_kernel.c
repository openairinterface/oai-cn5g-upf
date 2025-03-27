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
  struct session_qfi* session = data_meta;
  if ((void*) (session + 1) > data) {
    // TODO [QOS] assign default QFI
    bpf_debug("Error: Failed to load metadata from XDP");
    return TC_ACT_SHOT;
  }

  bpf_debug("TC: Received XDP Metadata - SEID: %d, QFI: %d", session->seid,
            session->qfi);

  skb->tc_classid = GET_TC_CLASSID(session->seid, session->qfi);
  bpf_debug("TC: classid %x", skb->tc_classid);
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

/***** End of adaptation *****/

/*---------------------------------------------------------------------------------------------------------------*/

SEC("classifier")
int tc_filter_traffic(struct __sk_buff* skb) {
  bpf_debug("==========< TC Egress >==========\n");

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

  void* data     = (void*) (long) skb->data;
  void* data_end = (void*) (long) skb->data_end;

  struct ethhdr* ethh = data;

  if ((void*) (ethh + 1) > data_end) {
    bpf_debug("Error: Invalid Ethernet header");
    return TC_ACT_SHOT;
  }

  // If not an IPv4 packet, drop it
  if (ethh->h_proto != htons(ETH_P_IP)) {
    bpf_debug("Not an IPv4 packet, pass");
    return TC_ACT_OK;
  }

  struct iphdr* iph = (void*) (ethh + 1);

  if ((void*) (iph + 1) > data_end) {
    bpf_debug("Error: Invalid IPv4 Packet");
    return TC_ACT_SHOT;
  }
  
  u8 protocol = iph->protocol;
  
  // If this is a GTP packet, go to inner IP header
  if (protocol == IPPROTO_UDP) {
    struct udphdr* udph = (struct udphdr*) (iph + 1);
    
    if ((void*) (udph + 1) > data_end) {
      bpf_debug("Error: Invalid UDP header");
      return TC_ACT_SHOT;
    }
    
    if (htons(udph->dest) != GTP_UDP_PORT) {
      bpf_debug("This is a GTP traffic");
      return TC_ACT_OK;
    }
  }
  
  // Inner IP header
  struct iphdr* iph_inner = (void*) (data + sizeof(struct ethhdr) + GTP_ENCAPSULATED_SIZE);
  if ((void*) (iph_inner + 1) > data_end) {
    bpf_debug("Error: Invalid Inner IP header");
    return TC_ACT_SHOT;
  }

  u32 ip_dest = iph_inner->daddr;


  struct filter_key filter_key = {0};


  bpf_debug("Shaping IP DST: %pI4", &ip_dest);

  // TODO [QOS]: Support for source IP
  filter_key.src_ip   = 0; // bpf_htonl(iph->saddr);
  filter_key.dst_ip   = ip_dest;
  // TODO [QOS]: Support for protocol
  filter_key.protocol = 0; // iph->protocol;
  // TODO [QOS]: Support for TOS
  filter_key.tos      = 0; // iph->tos;

  switch (protocol) {
    case IPPROTO_UDP: {
      struct udphdr* udph = (struct udphdr*) (iph + 1);

      if ((void*) (udph + 1) > data_end) {
        bpf_debug("Error: Invalid UDP header");
        return XDP_DROP;
      }

      // TODO [QOS]: Support for src port
      // key->src_port = udph->source;
      // TODO [QOS]: Support for dst port
      filter_key.dst_port = 0; // udph->dest;
      break;
    }
    case IPPROTO_TCP: {
      struct tcphdr* tcph = (struct tcphdr*) (iph + 1);

      if ((void*) (tcph + 1) > data_end) {
        bpf_debug("Error: Invalid TCP header");
        return XDP_DROP;
      }

      // TODO [QOS]: Support for src port
      // key->src_port = tcph->source;
      // TODO [QOS]: Support for dst port
      filter_key.dst_port = 0; // tcph->dest;
      break;
    }
    default: {
      bpf_debug("Unknown header");
      bpf_debug("Use best effort QoS flow (i.e. default qfi)");
      filter_key.dst_port = 0; // 65535;
    }
  }

  // Print filter key
  bpf_debug("Shaping IP DST: %d", filter_key.dst_ip);
  bpf_debug("Shaping Protocol: %d", filter_key.protocol);
  bpf_debug("Shaping Port: %d", filter_key.dst_port);
  bpf_debug("Shaping TOS: %d", filter_key.tos);
  bpf_debug("Shaping SRC IP: %d", filter_key.src_ip);


  struct session_qfi* session;
  session = (struct session_qfi*) skb->data_meta;
  if ((void*) (session + 1) > data) {
    bpf_debug("Error: Invalid Metadata");
    return TC_ACT_SHOT;
  }

  session->seid = 2;

  struct session_qfi* retrieved_value =
      bpf_map_lookup_elem(&m_sdf_filter, &filter_key); 

  if (retrieved_value) {
    session->qfi = retrieved_value->qfi;
    session->seid = retrieved_value->seid;
    bpf_debug("TC: Retrieved QFI: %d", session->qfi);
    bpf_debug("TC: Retrieved SEID: %d", session->seid);
  }

  int key = DOWNLINK, *ifindex;
  ifindex = bpf_map_lookup_elem(&m_egress_ifindex, &key);

  if (ifindex) {
    bpf_debug("TC_REDIRECT: Redirecting packet to N3 tc layer");
    return bpf_redirect(*ifindex, 0);
  }

  bpf_debug("TC Packets are not redirected! Drop them");
  return TC_ACT_SHOT;

}

char _license[] SEC("license") = "GPL";
/*---------------------------------------------------------------------------------------------------------------*/
