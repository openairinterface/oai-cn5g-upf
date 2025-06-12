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
#include "sdf_filter.h"

#include <linux/pkt_cls.h>
#include <qer_maps.h>

#include <linux/netdevice.h>
#include <linux/pkt_sched.h>

//#define __TC_H_MAKE(major, minor) (((major) << 16) | (minor))

//---------------------------------------------------------------------------------------------------------------
// SEC("tc/egress")
// egress_cls_func is called for packets that are going out of the network
// SEC("classifier/egress")
SEC("classifier")
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
      // return ipv4_sdf_filter(skb);

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
          // return egress_sdf_classifier(skb);

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

          void* data_meta = (void*) (long) skb->data_meta;
          struct session_qfi* qos_class_metadata = data_meta;

          /* Check XDP gave us some data_meta */
          if ((void*) (qos_class_metadata + 1) > data) {
            bpf_debug("Error: Failed to load metadata from XDP");
            return TC_ACT_SHOT;
          }

          bpf_debug(
              "TC: Received XDP Metadata - seid: %llu, qfi: %u",
              qos_class_metadata->seid, qos_class_metadata->qfi);

          u16 minor_id = generate_minor_id(
              qos_class_metadata->seid, qos_class_metadata->qfi);
          __u32 classid = TC_H_MAKE(1, minor_id);

          skb->tc_index   = classid;
          skb->tc_classid = classid;

          // skb->tc_index   = (1 << 16) | minor_id;
          // skb->tc_classid = (1 << 16) | minor_id;

          // skb->priority   = TC_H_MAKE(
          //     1, minor_id);  // 1 is the HTB root handle's major number
          bpf_debug("classid = 0x%x", classid);
          // bpf_debug("TC: classid 0x%x", skb->tc_classid);
          // bpf_debug("TC: indexid 0x%x", skb->tc_index);
          return TC_ACT_OK;
        }
      }

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

SEC("tc/ingress")
int tc_redirect_traffic(struct __sk_buff* skb) {
  bpf_debug("==========< tc/ingress: Redirect Traffic >==========");

  void* data     = (void*) (long) skb->data;
  void* data_end = (void*) (long) skb->data_end;

  struct session_qfi* qos_class_metadata;
  qos_class_metadata = (struct session_qfi*) (long) skb->data_meta;

  /* Check XDP gave us some data_meta */
  if ((void*) (qos_class_metadata + 1) > data) {
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