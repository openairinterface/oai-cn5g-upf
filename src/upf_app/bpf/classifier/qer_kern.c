#include <bpf_helpers.h>
#include <linux/bpf.h>
#include <types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

struct qoe_metrics {
  __u32 source_ip;
  __u32 destination_ip;
  __u16 source_port;
  __u16 destination_port;
  __u32 sequence_number;
  __u32 ack_number;
  // Add more QoE metrics as needed
};

struct pfcp_session_request {
  __u32 source_ip;
  __u32 destination_ip;
  __u16 source_port;
  __u16 destination_port;
  // Add more session request fields as needed
};

struct bpf_map_def SEC("maps") qoe_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(struct qoe_metrics),
    .max_entries = 1024,
};

struct bpf_map_def SEC("maps") pfcp_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(struct pfcp_session_request),
    .max_entries = 1024,
};

SEC("filter")
int qoe_pfcp_monitor(struct __sk_buff* skb) {
  // Extract Ethernet header
  struct ethhdr* eth = bpf_hdr_pointer(skb);

  // Filter IP packets
  if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

  // Extract IP header
  struct iphdr* ip = (struct iphdr*) (eth + 1);

  // Filter TCP packets
  if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

  // Extract TCP header
  struct tcphdr* tcp = (struct tcphdr*) (ip + 1);

  // Extract QFI from the IP header
  __u8 qfi = (__u8) (ip->tos & 0x3F);

  // Filter packets based on the QFI value
  if (qfi == 5) {
    // Extract QoE metrics
    struct qoe_metrics metrics = {
        .source_ip        = ip->saddr,
        .destination_ip   = ip->daddr,
        .source_port      = tcp->source,
        .destination_port = tcp->dest,
        .sequence_number  = tcp->seq,
        .ack_number       = tcp->ack_seq,
        // Add more QoE metric extraction here
    };

    // Store QoE metrics in the map
    __u32 key = bpf_get_smp_processor_id();
    bpf_map_update_elem(&qoe_map, &key, &metrics, BPF_ANY);
  }

  // Check if it's a PFCP session request
  if (tcp->dest == __constant_htons(8805)) {
    struct pfcp_session_request request = {
        .source_ip        = ip->saddr,
        .destination_ip   = ip->daddr,
        .source_port      = tcp->source,
        .destination_port = tcp->dest,
        // Extract and store more session request fields as needed
    };

    // Store PFCP session request in the map
    __u32 key = bpf_get_smp_processor_id();
    bpf_map_update_elem(&pfcp_map, &key, &request, BPF_ANY);
  }

  return XDP_PASS;
}