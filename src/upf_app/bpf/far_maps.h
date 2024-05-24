#ifndef __FAR_MAPS_H__
#define __FAR_MAPS_H__

#include <bpf_helpers.h>
#include <linux/bpf.h>
#include <pfcp/pfcp_far.h>
#include <types.h>
#include "arp_table_maps.h"

#define MAX_INTERFACES 10
#define ARP_ENTRIES_MAX_SIZE 12
#define FAR_TAILS_MAX 1

/*****************************************************************************************************************/
// The unique FAR that will be consumed in this program.

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, FAR_TAILS_MAX);  // 1,
  __type(key, u8);
  __type(value, pfcp_far_t_);
} m_far SEC(".maps");

/*****************************************************************************************************************/
struct {
  __uint(type, BPF_MAP_TYPE_DEVMAP);
  __uint(max_entries, MAX_INTERFACES);  // 10,
  __type(key, u32);                     // id
  __type(value, u32);                   // tx port
} m_redirect_interfaces SEC(".maps");

/*****************************************************************************************************************/
// Static ARP Table. Used to get the MAC address of the next hop.
// TODO: Pin this maps. It does not depend on the session program
// struct bpf_map_def SEC("maps") m_arp_table = {
//     .type        = BPF_MAP_TYPE_HASH,
//     .key_size    = sizeof(u32),           // IPv4 address
//     .value_size  = 6,                     // MAC address
//     .max_entries = ARP_ENTRIES_MAX_SIZE,  // 2,
// };

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, ARP_ENTRIES_MAX_SIZE);  // 2,
  __type(key, u32);                           // IPv4 address
  __type(value, struct s_arp_mapping);        // <IP Address, MAC address>
} m_arp_table SEC(".maps");
/*****************************************************************************************************************/
// BPF_ANNOTATE_KV_PAIR(m_far, u8, pfcp_far_t_);
// BPF_ANNOTATE_KV_PAIR(m_redirect_interfaces, u32, u32);
// BPF_ANNOTATE_KV_PAIR(m_arp_table, u32, ??);

#endif  // __FAR_MAPS_H__
