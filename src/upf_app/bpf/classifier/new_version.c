#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf_helpers.h>
#include <types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/filter.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_link.h>

struct qfi_data {
  __u32 qfi;
};

struct bpf_map_def SEC("maps") qfi_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(struct qfi_data),
    .max_entries = 1024,
};

struct qer_data {
  __u32 qfi;
  __u64 token_bucket_size;
  __u64 rate;
};

struct bpf_map_def SEC("maps") qer_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(struct qer_data),
    .max_entries = 1024,
};

struct bpf_map_def SEC("maps") token_bucket_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u64),
    .max_entries = 1024,
};

SEC("classifier")
int qfi_classifier(struct __sk_buff* skb) {
  // Extract Ethernet header
  struct ethhdr* eth = bpf_hdr_pointer(skb);

  // Filter IP packets
  if (eth->h_proto != __constant_htons(ETH_P_IP)) return TC_ACT_OK;

  // Extract IP header
  struct iphdr* ip = (struct iphdr*) (eth + 1);

  // Filter TCP packets
  if (ip->protocol != IPPROTO_TCP) return TC_ACT_OK;

  // Extract TCP header
  struct tcphdr* tcp = (struct tcphdr*) (ip + 1);

  // Classify packets based on destination port
  __u32 qfi;
  if (tcp->dest == __constant_htons(80)) {
    qfi = 1;
  } else if (tcp->dest == __constant_htons(443)) {
    qfi = 2;
  } else {
    qfi = 0;
  }

  // Store the QFI in the packet data
  struct qfi_data qfi_data = {
      .qfi = qfi,
  };
  bpf_map_update_elem(&qfi_map, &qfi, &qfi_data, BPF_ANY);

  // Store the QFI in the packet data
  struct qfi_data* qfi_data = bpf_map_lookup_elem(&qfi_map, &qfi);
  if (!qfi_data) {
    // QFI not configured, drop the packet
    return TC_ACT_SHOT;
  }
  skb->cb[0] = qfi_data->qfi;

  return TC_ACT_OK;
}

SEC("traffic_shape")
int token_bucket_filter(struct __sk_buff* skb) {
  // Retrieve the QFI from the packet data
  __u32 qfi = (__u32) skb->cb[0];

  // Retrieve QER data based on QFI
  struct qer_data* qer = bpf_map_lookup_elem(&qer_map, &qfi);
  if (!qer) {
    // QER not configured for the QFI, allow the packet
    return TC_ACT_OK;
  }

  // Retrieve token bucket for the QFI
  __u64* tokens = bpf_map_lookup_elem(&token_bucket_map, &qfi);
  if (!tokens) {
    // Token bucket not initialized, allow the packet
    return TC_ACT_OK;
  }

  // Calculate tokens based on rate
  __u64 elapsed_time = bpf_ktime_get_ns() / 1000 - qer->token_bucket_size;
  __u64 tokens_per_sec =
      qer->rate / 1000000;  // Convert rate from bps to tokens per microsecond
  __u64 elapsed_tokens = elapsed_time * tokens_per_sec;

  // Refill token bucket
  *tokens = *tokens + elapsed_tokens;
  if (*tokens > qer->token_bucket_size) {
    *tokens = qer->token_bucket_size;
  }

  // Consume tokens for the packet
  __u64 packet_size = (__u64) skb->len;
  if (packet_size > *tokens) {
    // Insufficient tokens, drop the packet
    return TC_ACT_SHOT;
  }

  *tokens = *tokens - packet_size;

  return TC_ACT_OK;
}

SEC("traffic_shape")
int token_bucket_filter(struct __sk_buff* skb) {
  // Extract Ethernet header
  struct ethhdr* eth = bpf_hdr_pointer(skb);

  // Filter IP packets
  if (eth->h_proto != __constant_htons(ETH_P_IP)) return TC_ACT_OK;

  // Extract IP header
  struct iphdr* ip = (struct iphdr*) (eth + 1);

  // Filter TCP packets
  if (ip->protocol != IPPROTO_TCP) return TC_ACT_OK;

  // Extract TCP header
  struct tcphdr* tcp = (struct tcphdr*) (ip + 1);

  // Extract QFI from the IP header
  __u8 qfi = (__u8) (ip->tos & 0x3F);

  // Retrieve QER data based on QFI
  struct qer_data* qer = bpf_map_lookup_elem(&qer_map, &qfi);
  if (!qer) {
    // QER not configured for the QFI, allow the packet
    return TC_ACT_OK;
  }

  // Retrieve token bucket for the QFI
  __u64* tokens = bpf_map_lookup_elem(&token_bucket_map, &qfi);
  if (!tokens) {
    // Token bucket not initialized, allow the packet
    return TC_ACT_OK;
  }

  // Calculate tokens based on rate
  __u64 elapsed_time = bpf_ktime_get_ns() / 1000 - qer->token_bucket_size;
  __u64 new_tokens   = elapsed_time * qer->rate / 1000000;
  if (new_tokens > qer->token_bucket_size) {
    new_tokens = qer->token_bucket_size;
  }
  qer->token_bucket_size = new_tokens;

  if (*tokens >= skb->len) {
    // Sufficient tokens available, consume tokens and allow the packet
    *tokens -= skb->len;
    return TC_ACT_OK;
  } else {
    // Insufficient tokens, drop the packet
    return TC_ACT_SHOT;
  }
}