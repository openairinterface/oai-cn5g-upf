#ifndef BPF_UTILS_H
#define BPF_UTILS_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <sys/socket.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <stdbool.h>
#include <interfaces.h>
// #include <arp_table_maps.h>
#include <far_maps.h>
#include <pfcp_session_lookup_maps.h>

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

/*****************************************************************************************************************/

static __always_inline bool retrieve_upf_iface_from_map(
    e_reference_point key, u32* iface_ip) {
  struct s_interface* map_element =
      bpf_map_lookup_elem(&m_upf_interfaces, &key);

  if (map_element) {
    *iface_ip = map_element->ipv4_address;
    return true;
  }

  return false;
}

/*****************************************************************************************************************/
static __always_inline bool update_dst_mac_address(
    u32 ip, struct ethhdr* p_eth) {
  struct s_arp_mapping* map_entry = {0};
  // memset(&map_entry, 0, sizeof(struct s_arp_mapping));

  map_entry = bpf_map_lookup_elem(&m_arp_table, &ip);

  if (map_entry) {
    __builtin_memcpy(
        p_eth->h_dest, map_entry->mac_address, sizeof(p_eth->h_dest));
    return true;
  }

  return false;
}

/*
 * Update the MAC address based on the FIB lookup
 */
static __always_inline int update_mac_address(
    struct xdp_md* ctx, struct ethhdr* ethh, struct iphdr* iph,
    e_reference_point direction) {
  void* data_end = (void*) (long) ctx->data_end;

  struct bpf_fib_lookup fib_params = {};
  __u16 h_proto                    = ethh->h_proto;
  if (h_proto == bpf_htons(ETH_P_IP)) {
    if ((void*) iph + 1 > data_end) {
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

      __builtin_memcpy(ethh->h_dest, fib_params.dmac, ETH_ALEN);
      __builtin_memcpy(ethh->h_source, fib_params.smac, ETH_ALEN);
      break;
    case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped
                                         */
    case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be
                                           dropped */
    case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
    case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
    case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress
                                         */
    case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
    case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
    case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
      /* PASS */
      bpf_debug("BPF_FIB_LOOKUP Failed, rc: %d, try the UPF arp table", rc);

      // Retrieve the N6 Interface IP address:
      e_reference_point nx_key = direction;
      u32 nx_ip;
      if (retrieve_upf_iface_from_map(nx_key, &nx_ip)) {
        if (!update_dst_mac_address(nx_ip, ethh)) {
          bpf_debug("N6's Next Hop MAC address not found! Do nothing");
        }
      }

      break;
  }
  return rc;
}
#endif
