/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#define KBUILD_MODNAME qer_tc_kern

/* ========================================================================== */
/*                              SYSTEM INCLUDES                               */
/* ========================================================================== */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/netdevice.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <endian.h>
#include <string.h>
#include <stdbool.h>

/* ========================================================================== */
/*                             PROJECT INCLUDES                               */
/* ========================================================================== */

#include "linux/custom_types.h"
// #include "xdp_stats_kern.h"
#include "pfcp/pfcp_far.h"
#include "pfcp/pfcp_pdr.h"
#include "protocols/gtpu.h"
#include "utils/csum.h"
#include "utils/logger.h"
#include "utils/bpf_utils.h"
/* interfaces_maps.h removed: qer_tc_kern.c uses none of upf_interface_map /
 * arp_table_map / redirect_interfaces_map; including the header would
 * materialise dead per-program copies at load time. */
#include "qer_maps.h"
#include "sdf_types.h"
/* ========================================================================== */
/*                          CONSTANTS AND MACROS                              */
/* ========================================================================== */
/**
 * @brief TC classid generation
 *
 * Creates a 32-bit TC classid (handle) from major and minor numbers.
 * Format: [major:16][minor:16]
 *
 * The kernel provides this as TC_H_MAKE, but we redefine it for clarity.
 */
#ifndef TC_H_MAKE
#define TC_H_MAKE(major, minor) (((major) << 16) | (minor))
#endif

/**
 * @brief HTB root handle major number
 *
 * All QoS flows use major number 1, matching the HTB qdisc root handle
 * configured from userspace (typically 1:0).
 */
#define HTB_ROOT_MAJOR 1

/* ========================================================================== */
/*                          TC EGRESS CLASSIFIER                              */
/* ========================================================================== */

/**
 * @brief TC egress traffic classifier and QoS flow marker
 *
 * This function is the main egress classifier that runs on the TC layer
 * for outgoing packets (typically on the N3 interface). It:
 *
 * 1. Extracts QoS metadata (seid, qfi) passed from XDP layer
 * 2. Validates packet headers (Ethernet, IP, UDP, GTP-U)
 * 3. Looks up QER rules for the flow
 * 4. Generates TC classid for HTB/FQ_CODEL integration
 * 5. Sets skb->tc_classid to enable per-flow rate limiting
 *
 * Packet Flow:
 * ```
 * [XDP] → [XDP metadata: seid, qfi] → [TC Egress: this function]
 *    ↓
 * [Set skb->tc_classid = 0x00010XXX]
 *    ↓
 * [TC Qdisc (HTB/FQ_CODEL) applies rate limiting]
 *    ↓
 * [TC Ingress or egress to N3]
 * ```
 *
 * TC Classid Format:
 * - Major: 1 (HTB root handle)
 * - Minor: Hash(seid, qfi) - unique per QoS flow
 * - Example: 0x00010A3F (major=1, minor=0x0A3F)
 *
 * Return Values:
 * - TC_ACT_OK: Continue processing (normal path)
 * - TC_ACT_SHOT: Drop packet (error)
 *
 * Expected Setup (userspace):
 * ```bash
 * # Create HTB qdisc with root handle 1:0
 * tc qdisc add dev eth0 root handle 1:0 htb default 1
 *
 * # Create classes for each QoS flow (done dynamically)
 * tc class add dev eth0 parent 1:0 classid 1:100 htb rate 1mbit
 * tc class add dev eth0 parent 1:0 classid 1:200 htb rate 10mbit
 * ```
 *
 * @param skb Socket buffer containing packet data and metadata
 * @return TC action code (TC_ACT_OK or TC_ACT_SHOT)
 */
// SEC("tc/egress")
// egress_cls_func is called for packets that are going out of the network
// SEC("classifier/egress")
SEC("classifier")
int tc_filter_traffic(struct __sk_buff* skb) {
  bpf_debug("==========< tc/egress: Filter Traffic >==========");

  void* data     = (void*) (long) skb->data;
  void* data_end = (void*) (long) skb->data_end;

  /* Parse Ethernet header */
  struct ethhdr* ethh = data;
  if ((void*) (ethh + 1) > data_end) {
    bpf_debug("Error: Invalid Ethernet header");
    return TC_ACT_SHOT;
  }

  u16 l3_protocol = htons(ethh->h_proto);
  bpf_debug("TC Egress: L3 protocol: 0x%x", l3_protocol);

  /* Only process IPv4 GTP-U traffic */
  if (l3_protocol != ETH_P_IP) {
    /* Pass through non-IPv4 traffic (ARP, IPv6, VLAN, etc.) */
    return TC_ACT_OK;
  }

  bpf_debug("TC Egress: Processing IPv4 packet");

  /* Parse IPv4 header */
  struct iphdr* iph = (struct iphdr*) (ethh + 1);
  if ((void*) (iph + 1) > data_end) {
    bpf_debug("Error: Invalid IPv4 header");
    return TC_ACT_SHOT;
  }

  /* Only process UDP traffic (GTP-U uses UDP) */
  if (iph->protocol != IPPROTO_UDP) {
    /* Not UDP traffic, pass through */
    return TC_ACT_OK;
  }

  /* Parse UDP header */
  struct udphdr* udph = (struct udphdr*) (iph + 1);
  if ((void*) (udph + 1) > data_end) {
    bpf_debug("Error: Invalid UDP header");
    return TC_ACT_SHOT;
  }

  /* Check if this is GTP-U traffic (port 2152) */
  if (bpf_htons(udph->dest) != GTP_UDP_PORT) {
    /* Not GTP-U traffic, pass through */
    return TC_ACT_OK;
  }

  bpf_debug("TC Egress: Detected GTP-U traffic (port 2152)");

  /* Parse GTP-U header */
  struct gtpuhdr* gtpuh = (struct gtpuhdr*) (udph + 1);
  if ((void*) (gtpuh + 1) > data_end) {
    bpf_debug("Error: Invalid GTP-U header");
    return TC_ACT_SHOT;
  }

  /* Parse GTP-U extension header (PDU Session Container) */
  struct gtpu_extn_pdu_session_container* gtpu_ext_h =
      (struct gtpu_extn_pdu_session_container*) ((void*) (gtpuh + 1));
  if ((void*) (gtpu_ext_h + 1) > data_end) {
    bpf_debug("Error: Invalid GTP-U extension header");
    return TC_ACT_SHOT;
  }

  /* Extract QoS Metadata from XDP */
  void* data_meta                        = (void*) (long) skb->data_meta;
  struct session_qfi* qos_class_metadata = data_meta;

  /* Verify XDP passed valid metadata */
  if ((void*) (qos_class_metadata + 1) > data) {
    bpf_debug("Error: Failed to load QoS metadata from XDP");
    bpf_debug("XDP must set metadata using bpf_xdp_adjust_meta()");
    return TC_ACT_SHOT;
  }

  u64 seid = qos_class_metadata->seid;
  u8 qfi   = qos_class_metadata->qfi;

  bpf_debug(
      "TC Egress: Received QoS metadata - SEID: %llu, QFI: %u", seid, qfi);

  /* Generate unique minor ID for this QoS flow */
  u16 minor_id = generate_minor_id(seid, qfi);

  /* Create TC classid (handle): major=1, minor=minor_id */
  u32 classid = TC_H_MAKE(HTB_ROOT_MAJOR, minor_id);

  /* Set TC classid for HTB/FQ_CODEL to apply rate limiting */
  skb->tc_classid = classid;
  skb->tc_index   = classid;

  bpf_debug(
      "TC Egress: Set tc_classid = 0x%08x (major=%u, minor=%u)", classid,
      HTB_ROOT_MAJOR, minor_id);

  /* Continue Processing*/
  bpf_debug("TC Egress: QoS classification complete, passing to qdisc");
  return TC_ACT_OK;
}

/* ========================================================================== */
/*                          TC INGRESS REDIRECT                               */
/* ========================================================================== */

/**
 * @brief TC ingress traffic redirect
 *
 * This function runs on the TC ingress hook and redirects packets to the
 * appropriate egress interface (typically N3 for downlink GTP-U traffic).
 *
 * Packet Flow:
 * ```
 * [TC Egress Classifier] → [TC Qdisc (rate shaping)]
 *         ↓
 * [TC Ingress: this function] → [Redirect to N3 interface]
 * ```
 *
 * The function:
 * 1. Validates QoS metadata from XDP
 * 2. Parses Ethernet header
 * 3. For IPv4 packets, looks up egress interface
 * 4. Redirects packet to target interface using bpf_redirect()
 *
 * Expected Setup (userspace):
 * ```c
 * // Set egress interface index (N3 interface)
 * int key = DOWNLINK;
 * int ifindex = if_nametoindex("eth0");  // N3 interface
 * bpf_map_update_elem(egress_ifindex_fd, &key, &ifindex, BPF_ANY);
 * ```
 *
 * @param skb Socket buffer containing packet data and metadata
 * @return TC action code (TC_ACT_REDIRECT, TC_ACT_OK, or TC_ACT_SHOT)
 */
SEC("tc/ingress")
int tc_redirect_traffic(struct __sk_buff* skb) {
  bpf_debug("==========< tc/ingress: Redirect Traffic >==========");

  void* data     = (void*) (long) skb->data;
  void* data_end = (void*) (long) skb->data_end;

  struct session_qfi* qos_class_metadata;
  qos_class_metadata = (struct session_qfi*) (long) skb->data_meta;

  /* Check if XDP passed valid metadata */
  if ((void*) (qos_class_metadata + 1) > data) {
    bpf_debug("Error: Failed to load QoS metadata from XDP");
    return TC_ACT_SHOT;
  }

  bpf_debug(
      "TC Ingress: QoS metadata - SEID: %llu, QFI: %u",
      qos_class_metadata->seid, qos_class_metadata->qfi);

  struct ethhdr* ethh = data;
  if ((void*) (ethh + 1) > data_end) {
    bpf_debug("Error: Invalid Ethernet header");
    return TC_ACT_SHOT;
  }

  u16 l3_protocol = htons(ethh->h_proto);
  bpf_debug("TC Ingress: L3 protocol: 0x%x", l3_protocol);

  switch (l3_protocol) {
    case ETH_P_IP: {
      bpf_debug("TC Ingress: Processing IPv4 packet for redirect");

      /* Look up egress interface index */
      int key      = DOWNLINK;
      int* ifindex = bpf_map_lookup_elem(&egress_ifindex, &key);

      if (ifindex) {
        bpf_debug("TC Ingress: Redirecting to interface %d (N3)", *ifindex);
        return bpf_redirect(*ifindex, 0);
      }

      /* No egress interface configured - drop packet */
      bpf_debug("TC Ingress: No egress interface configured, dropping packet");
      return TC_ACT_SHOT;
    }

    /* Pass through non-IPv4 traffic */
    case ETH_P_IPV6:
    case ETH_P_8021Q:
    case ETH_P_8021AD:
    case ETH_P_ARP:
      bpf_debug("TC Ingress: Passing through non-IPv4 traffic");
      return TC_ACT_OK;

    default:
      bpf_debug(
          "TC Ingress: Unknown protocol 0x%x, passing through", l3_protocol);
      return TC_ACT_OK;
  }
}

/* ========================================================================== */
/*                          LICENSE DECLARATION                               */
/* ========================================================================== */

char _license[] SEC("license") = "GPL";
