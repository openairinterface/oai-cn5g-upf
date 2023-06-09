#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf_helpers.h>
#include <types.h>

struct qfi_data {
  __u32 qfi;
};

struct bpf_map_def SEC("maps") qfi_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(struct qfi_data),
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
  struct qfi_data* qfi_data = bpf_map_lookup_elem(&qfi_map, &qfi);
  if (!qfi_data) {
    // QFI not configured, drop the packet
    return TC_ACT_SHOT;
  }
  skb->cb[0] = qfi_data->qfi;

  return TC_ACT_OK;
}