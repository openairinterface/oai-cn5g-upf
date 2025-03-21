#define KBUILD_MODNAME pfcp_session_lookup_xdp_kernel

// clang-format off
#include <types.h>
// clang-format on
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <endian.h>
#include <lib/crc16.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <protocols/eth.h>
#include <protocols/gtpu.h>
#include <protocols/ip.h>
#include <protocols/udp.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <pfcp_session_lookup_maps.h>
#include <utils/logger.h>
#include <utils/utils.h>
#include <next_prog_rule_key.h>

#ifdef KERNEL_SPACE
#include <linux/in.h>
#else
#include <netinet/in.h>
#endif
#include <stdio.h>

/* Defines xdp_stats_map */
#include "xdp_stats_kern.h"
#include "xdp_stats_kern_user.h"

struct vlan_hdr {
  __be16 h_vlan_TCI;
  __be16 h_vlan_encapsulated_proto;
};

struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key, __u32);
        __type(value, long);
        __uint(max_entries, 12);
} rxcnt SEC(".maps");


// #define SAMPLE_SIZE 1024ul
// #define MAX_CPUS 128

// #ifndef __packed
// #define __packed __attribute__((packed))
// #endif

// #define min(x, y) ((x) < (y) ? (x) : (y))

// /* Metadata will be in the perf event before the packet data. */
// struct S {
// 	__u16 cookie;
// 	__u16 pkt_len;
//   char message[128];
// } __packed;
// struct {
// 	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
// 	__type(key, int);
// 	__type(value, 256);
// 	__uint(max_entries, MAX_CPUS);
//   __uint(pinning, 1);
// } logs_map SEC(".maps");

/*****************************************************************************************************************/

static __always_inline u32 tail_call_next_prog(
    struct xdp_md* ctx, teid_t_ teid, u8 source_value, u32 ipv4_address) {
  struct next_rule_prog_index_key map_key;

  __u32 key = 5;
  long *value;

  value = bpf_map_lookup_elem(&rxcnt, &key);
  if (value)
      *value += 1;

  __builtin_memset(&map_key, 0, sizeof(struct next_rule_prog_index_key));
  map_key.teid         = teid;
  map_key.source_value = source_value;
  map_key.ipv4_address = ipv4_address;

  u32* index_prog = bpf_map_lookup_elem(&m_next_rule_prog_index, &map_key);

  if (index_prog) {
    bpf_debug3(ctx, "Value of the eBPF tail call, index_prog = %d", *index_prog);
    key = 6;

    value = bpf_map_lookup_elem(&rxcnt, &key);
    if (value)
        *value += 1;
    bpf_tail_call(ctx, &m_next_rule_prog, *index_prog);
  }

  bpf_debug3(ctx, "BPF tail call was not executed!");
  bpf_debug3(ctx, "Check your key and its endianess");
  key = 7;

  value = bpf_map_lookup_elem(&rxcnt, &key);
  if (value)
      *value += 1;

  return XDP_DROP;
}

/*---------------------------------------------------------------------------------------------------------------*/

static __always_inline u32
handle_downlink_traffic(struct xdp_md* ctx, u32 ue_ip_address) {
  __u32 key = 10;
  long *value;

  value = bpf_map_lookup_elem(&rxcnt, &key);
  if (value)
      *value += 1;
  struct session_id* session =
      bpf_map_lookup_elem(&m_session_mapping, &ue_ip_address);

  if (session) {
    key = 9;
    value = bpf_map_lookup_elem(&rxcnt, &key);
    if (value)
        *value += 1;
    u32 teid_dl = session->teid_dl;
    bpf_debug3(ctx, 
        "TEID downlink: 0x%x was found for UE IP: 0x%x", teid_dl,
        ue_ip_address);
    tail_call_next_prog(ctx, teid_dl, INTERFACE_VALUE_CORE, ue_ip_address);
  }

  key = 8;
  value = bpf_map_lookup_elem(&rxcnt, &key);
  if (value)
      *value += 1;
  bpf_debug3(ctx, "BPF tail call was not executed!");

  return XDP_PASS;
}

/*---------------------------------------------------------------------------------------------------------------*/
/**
 * Uplink SECTION.
 */

/**
 * @brief Handle UDP header.
 *
 * @param ctx The user accessible metadata for xdp packet hook.
 * @param udph The UDP header.
 * @return u32 The XDP action.
 */

static __always_inline u32
handle_uplink_traffic(struct xdp_md* ctx, struct udphdr* udph) {
  void* data     = (void*) (long) ctx->data;
  void* data_end = (void*) (long) ctx->data_end;

  __u32 key = 3;
  long *value;

  value = bpf_map_lookup_elem(&rxcnt, &key);
  if (value)
      *value += 1;

  struct gtpuhdr* gtpuh = (struct gtpuhdr*) (udph + 1);

  // Check if the GTP header extends beyond the data end.
  if ((void*) gtpuh + sizeof(*gtpuh) > data_end) {
    bpf_debug3(ctx, "Invalid GTPU packet");
    return XDP_DROP;
  }

  struct ethhdr* ethh_new = data + GTP_ENCAPSULATED_SIZE;

  if ((void*) ethh_new + sizeof(*ethh_new) > data_end) {
    bpf_debug3(ctx, "Invalid Ethernet packet");
    return XDP_DROP;
  }

  struct iphdr* iph_inner = (void*) (ethh_new + 1);

  if ((void*) iph_inner + sizeof(*iph_inner) > data_end) {
    bpf_debug3(ctx, "Invalid Inner IP packet");
    return XDP_DROP;
  }

  u32 src_ip_in = iph_inner->saddr;

  if (gtpuh->message_type != GTPU_G_PDU) {
    bpf_debug3(ctx, 
        "Message type 0x%x is not GTPU GPDU(0x%x)\n", gtpuh->message_type,
        GTPU_G_PDU);
    return XDP_PASS;
  }

  key = 4;

  value = bpf_map_lookup_elem(&rxcnt, &key);
  if (value)
      *value += 1;
  // Jump to session context.
  tail_call_next_prog(ctx, gtpuh->teid, INTERFACE_VALUE_ACCESS, src_ip_in);

  return XDP_PASS;
}

/*---------------------------------------------------------------------------------------------------------------*/

/**
 * IP SECTION.
 */

/**
 * @brief Handle IPv4 header.
 *
 * @param ctx The user accessible metadata for xdp packet hook.
 * @param iph The IP header.
 * @return u32 The XDP action.
 */

static __always_inline u32 ipv4_handle(struct xdp_md* ctx, struct iphdr* iph) {
  void* data_end = (void*) (long) ctx->data_end;

  u32 ip_dest = iph->daddr;
  u8 protocol = iph->protocol;

  __u32 key = 2;
  long *value;

  value = bpf_map_lookup_elem(&rxcnt, &key);
  if (value)
      *value += 1;

  switch (protocol) {
    case IPPROTO_UDP: {
      struct udphdr* udph = (struct udphdr*) (iph + 1);

      // Check if the UDP header extends beyond the data end.
      if ((void*) (udph + 1) > data_end) {
        bpf_debug3(ctx, "Invalid UDP packet");
        return XDP_DROP;
      }

      if (bpf_htons(udph->dest) == GTP_UDP_PORT) {
        bpf_debug3(ctx, "This is a GTP traffic");
        return handle_uplink_traffic(ctx, udph);
      }
    }
    default: {
      return handle_downlink_traffic(ctx, ip_dest);
    }
  }
}

/*---------------------------------------------------------------------------------------------------------------*/
/**
 * ETHERNET SECTION.
 */

/**
 *
 * @brief Parse Ethernet layer 2, extract network layer 3 offset and protocol
 * Call next protocol handler (e.g. ipv4).
 *
 * @param ctx
 * @param ethh
 * @return u32 The XDP action.
 */

static __always_inline u32 eth_handle(struct xdp_md* ctx, struct ethhdr* ethh) {
  void* data_end = (void*) (long) ctx->data_end;
  u16 eth_type   = bpf_htons(ethh->h_proto);
  u64 offset     = sizeof(*ethh);

  __u32 key = 1;
  long *value;

  value = bpf_map_lookup_elem(&rxcnt, &key);
  if (value)
      *value += 1;

  bpf_debug3(ctx, "Debug: eth_type:0x%x", eth_type);

  switch (eth_type) {
    case ETH_P_IP: {
      struct iphdr* iph = (struct iphdr*) ((void*) ethh + offset);

      if ((void*) (iph + 1) > data_end) {
        bpf_debug3(ctx, "Invalid IPv4 Packet");
        return XDP_DROP;
      }

      return ipv4_handle(ctx, iph);
    }
    case ETH_P_8021AD: {
      bpf_debug3(ctx, "VLAN!! Changing the offset");
      struct vlan_hdr* vlan_hdr = (struct vlan_hdr*) (ethh + 1);
      offset += sizeof(*vlan_hdr);
      if ((void*) (vlan_hdr + 1) <= data_end)
        eth_type = bpf_htons(vlan_hdr->h_vlan_encapsulated_proto);
    }
    case ETH_P_IPV6:
    case ETH_P_ARP:
    case ETH_P_8021Q:
    default: {
      bpf_debug3(ctx, "Cannot parse L2: L3off:%llu proto:0x%x", offset, eth_type);
      return XDP_PASS;
    }
  }
}

/*---------------------------------------------------------------------------------------------------------------*/
SEC("xdp")
int xdp_entry_point(struct xdp_md* ctx) {
  bpf_debug3(ctx, "================< PFCP PDR Sesction >================");

  __u64 flags = BPF_F_CURRENT_CPU;
  __u16 sample_size = (__u16)(ctx->data_end - ctx->data);
  struct S metadata;
  __u32 key = 0;
  long *value;

  key = 0;
  value = bpf_map_lookup_elem(&rxcnt, &key);
  if (value)
      *value += 1;

  // Print the current CPU
  bpf_debug3(ctx, "CPU: %d\n", bpf_get_smp_processor_id());

  struct ethhdr* ethh = (void*) (long) ctx->data;

  if ((void*) (ethh + 1) > (void*) (long) ctx->data_end) {
    bpf_debug3(ctx, "Invalid Ethernet header");
    return XDP_DROP;
  }

  return eth_handle(ctx, ethh);
}

char _license[] SEC("license") = "GPL";

/*---------------------------------------------------------------------------------------------------------------*/