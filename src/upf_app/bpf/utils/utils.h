#ifndef BPF_UTILS_H
#define BPF_UTILS_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <sys/socket.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>

// Dictionary
// htons() - host to network short
// htonl() - host to network long
// ntohs() - network to host short
// ntohl() - network to host long
// If not defined -> "failed to find BTF for extern"

#ifndef htons
#define htons(x) __constant_htons((x))
#endif

#ifndef htonl
#define htonl(x) __constant_htonl((x))
#endif

#ifndef ntohs
#define ntohs(x) __constant_ntohs((x))
#endif

#ifndef ntohl
#define ntohl(x) __constant_ntohl((x))
#endif

static void swap_src_dst_mac(struct ethhdr* eth) {
  __u8 h_tmp[ETH_ALEN];

  __builtin_memcpy(h_tmp, eth->h_source, ETH_ALEN);
  __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
  __builtin_memcpy(eth->h_dest, h_tmp, ETH_ALEN);
}

/*
 * Swaps destination and source IPv4 addresses inside an IPv4 header
 */
static void swap_src_dst_ipv4(struct iphdr* iphdr) {
  __be32 tmp = iphdr->saddr;

  iphdr->saddr = iphdr->daddr;
  iphdr->daddr = tmp;
}

/*
 * Update the MAC address based on the FIB lookup
 */
static __always_inline int update_mac_address(
    struct xdp_md* ctx, struct ethhdr* ethh, struct iphdr* iph) {
    void* data_end = (void*) (long) ctx->data_end;

    
    struct bpf_fib_lookup fib_params = {};
    __u16 h_proto = ethh->h_proto;
    if (h_proto == bpf_htons(ETH_P_IP)) {
      if (iph + 1 > data_end) {
        return -1;
      }

      fib_params.family      = AF_INET;
      fib_params.tos         = iph->tos;
      fib_params.l4_protocol = iph->protocol;
      fib_params.sport       = 0;
      fib_params.dport       = 0;
      fib_params.tot_len     = bpf_ntohs(iph->tot_len);
      fib_params.ipv4_src    = iph->saddr;
      fib_params.ipv4_dst    = iph->daddr;
    }

    fib_params.ifindex = ctx->ingress_ifindex;

    int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
    switch (rc) {
      case BPF_FIB_LKUP_RET_SUCCESS: /* lookup successful */
        bpf_debug("BPF_FIB_LKUP_RET_SUCCESS");

        memcpy(ethh->h_dest, fib_params.dmac, ETH_ALEN);
        memcpy(ethh->h_source, fib_params.smac, ETH_ALEN);
        break;
      case BPF_FIB_LKUP_RET_BLACKHOLE:   /* dest is blackholed; can be dropped
                                          */
      case BPF_FIB_LKUP_RET_UNREACHABLE: /* dest is unreachable; can be
                                            dropped */
      case BPF_FIB_LKUP_RET_PROHIBIT:  /* dest not allowed; can be dropped */
      case BPF_FIB_LKUP_RET_NOT_FWDED: /* packet is not forwarded */
      case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress
                                            */
      case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
      case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
      case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
        /* PASS */
        bpf_debug("BPF_FIB_LKUP_RET_ -> %d", rc);
        break;
    }
    return rc;
}
#endif
