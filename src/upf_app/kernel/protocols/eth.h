#if !defined(PROTOCOLS_ETH_H)
#define PROTOCOLS_ETH_H

#include <linux/if_ether.h>
#include <linux/bpf.h>
#include "linux/custom_types.h"

static u32 eth_handle(struct xdp_md* ctx, struct ethhdr* ethh);

#endif  // PROTOCOLS_ETH_H
