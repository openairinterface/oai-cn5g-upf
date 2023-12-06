#if !defined(PROTOCOLS_UDP_H)
#define PROTOCOLS_UDP_H

#include <linux/udp.h>
#include <types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>

#define UDP_CSUM_OFFSET (sizeof(struct ethhdr) + offsetof(struct udphdr, check))

// static u32 udp_handle(
//     struct xdp_md* ctx, struct udphdr* udph, u32 src_ip, u32 dest_ip);
// static u32 udp_handle(
//     struct xdp_md* ctx, struct udphdr* udph, u32 dest_ip);

static u32 udp_handle(
    struct xdp_md* p_ctx, struct udphdr* udph, u32 src_ip, u32 dest_ip,
    u8 dscp);

static u32 handle_uplink_traffic(struct xdp_md* p_ctx, struct udphdr* udph);

#endif  // PROTOCOLS_UDP_H
