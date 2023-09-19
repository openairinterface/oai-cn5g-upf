#if !defined(PROTOCOLS_TCP_H)
#define PROTOCOLS_TCP_H

#include <linux/tcp.h>
#include <types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>

#define TCP_CSUM_OFFSET                                                        \
  (sizeof(struct ethhdr) + sizeof(struct iphdr) +                              \
   offsetof(struct tcphdr, check))

// static u32 tcp_handle(struct xdp_md* ctx, struct iphdr* iph_outer);

#endif  // PROTOCOLS_TCP_H
