// clang-format off
#include <types.h>
// clang-format on

#include "xdp_stats_kern.h"
#include <bpf_helpers.h>
#include <endian.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <pfcp/pfcp_far.h>
#include <pfcp/pfcp_pdr.h>
#include <protocols/gtpu.h>
#include <protocols/ip.h>
#include <protocols/tcp.h>
#include <utils/csum.h>
#include <utils/logger.h>
#include <utils/utils.h>
#include <far_maps.h>
#include <far_data.h>
#include <interfaces.h>
#include <pfcp_session_lookup_maps.h>
#include <utils/gtpu_parse.h>
#include <string.h>  //Needed for memcpy
#include "bpf_endian.h"

const volatile struct far_config config;

// /*****************************************************************************************************************/

SEC("xdp")
int far_entry_point(struct xdp_md* ctx) {
  bpf_debug("================< FAR Sesction >================");
  void* data     = (void*) (long) ctx->data;
  void* data_end = (void*) (long) ctx->data_end;

  u32 key            = 0;
  pfcp_far_t_* p_far = bpf_map_lookup_elem(&m_far, &key);

  if (p_far) {
    struct ethhdr* ethh = data;

    if ((void*) (ethh + 1) > data_end) {
      bpf_debug("Invalid pointer");
      return XDP_DROP;
    }

    // Check if it is a forward action.
    u8 dest_interface =
        p_far->forwarding_parameters.destination_interface.interface_value;

    // u16 outer_header_creation =
    //     p_far->forwarding_parameters.outer_header_creation
    //         .outer_header_creation_description;

    // Check forwarding action
    if (!p_far->apply_action.forw) {
      bpf_debug("Forward Action Is NOT set");
      return XDP_PASS;
    }

    if (dest_interface == INTERFACE_VALUE_CORE) {
      // Redirect to data network.
      bpf_debug("GTP Header Removal ...");
      int roomlen = GTP_ENCAPSULATED_SIZE;
      if (config.pdu_type == 0) {

        struct ethhdr* p_new_eth = data + GTP_ENCAPSULATED_SIZE;

        if ((void*) (p_new_eth + 1) > data_end) {
          return XDP_DROP;
        }

        __builtin_memcpy(p_new_eth, ethh, sizeof(*ethh));

        // Retrieve the N6 Interface IP address:
        e_reference_point n6_key = N6_INTERFACE;
        u32 n6_ip;
        if (!retrieve_upf_iface_from_map(n6_key, &n6_ip)) {
          bpf_debug("N6 interface is missing in UPF map, Drop the packet");
          return XDP_DROP;
        }

        // Update destination mac address
        if (!update_dst_mac_address(n6_ip, p_new_eth)) {
          bpf_debug("N6's Next Hop MAC address not found! Drop the packet");
        }
      } else if (config.pdu_type == 1) { // ETH PDU session
        bpf_debug("far_xdp: handling eth pdu session packet");
        roomlen += sizeof(struct ethhdr);
      }

      // Adjust head to the right.
      if (bpf_xdp_adjust_head(ctx, roomlen)) {
        return XDP_DROP;
      }

      bpf_debug("The Packet is redirected for transmission to DN ...");

      return bpf_redirect_map(&m_redirect_interfaces, UPLINK, 0);

      bpf_debug("OUTER_HEADER_CREATION_UDP_IPV4 REDIRECT FAILED");

    } else if (dest_interface == INTERFACE_VALUE_ACCESS) {
      create_outer_header_gtpu(ctx, p_far->forwarding_parameters.outer_header_creation.teid, p_far->forwarding_parameters.outer_header_creation.ipv4_address.s_addr, 0);

      uint32_t far_id_key = p_far->far_id.far_id;
      uint32_t* enforcing_qos =
          bpf_map_lookup_elem(&m_enforcing_qos, &far_id_key);
      if (enforcing_qos) {
        switch (*enforcing_qos) {
          case 0: {
            bpf_debug("The packet is redirected to N3 interface");
            return bpf_redirect_map(&m_redirect_interfaces, DOWNLINK, 0);
          }
          case 1: {
            bpf_debug("The packet is passed to tc layer");
            return XDP_PASS;
          }
          default: {
          }
        }
      }
    }
  }

  bpf_debug("FAR Program NOT Found!");
  return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
/*---------------------------------------------------------------------------------------------------------------*/
