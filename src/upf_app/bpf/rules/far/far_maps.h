#ifndef __FAR_MAPS_H__
#define __FAR_MAPS_H__

#include <bpf_helpers.h>
#include <linux/bpf.h>
#include <pfcp/pfcp_far.h>
#include <types.h>
#include "arp_table_maps.h"

#define ARP_ENTRIES_MAX_SIZE 12
#define FAR_TAILS_MAX 1
#define MAX_INTERFACES 10
#define MAX_FAR_PROGRAMS 100
/*---------------------------------------------------------------------------------------------------------------*/
// The unique FAR that will be consumed in this program.

// struct bpf_map_def SEC("maps") m_far = {
//     .type        = BPF_MAP_TYPE_HASH,
//     .key_size    = sizeof(u8),
//     .value_size  = sizeof(pfcp_far_t_),
//     .max_entries = FAR_TAILS_MAX,  // 1,
// };

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, FAR_TAILS_MAX);  // 1,
  __type(key, u8);
  __type(value, pfcp_far_t_);
} m_far SEC(".maps");

/*---------------------------------------------------------------------------------------------------------------*/
// struct bpf_map_def SEC("maps") m_redirect_interfaces = {
//     .type        = BPF_MAP_TYPE_DEVMAP,
//     .key_size    = sizeof(u32),     // id
//     .value_size  = sizeof(u32),     // tx port
//     .max_entries = MAX_INTERFACES,  // 10,
// };

struct {
  __uint(type, BPF_MAP_TYPE_DEVMAP);
  __uint(max_entries, MAX_INTERFACES);  // 10,
  __type(key, u32);                     // id
  __type(value, u32);                   // tx port
} m_redirect_interfaces SEC(".maps");

/*---------------------------------------------------------------------------------------------------------------*/
// struct bpf_map_def SEC("maps") m_arp_table = {
//     .type        = BPF_MAP_TYPE_HASH,
//     .key_size    = sizeof(u32),                   // IPv4 address
//     .value_size  = sizeof(struct s_arp_mapping),  // <IP Address, MAC
//     address> .max_entries = ARP_ENTRIES_MAX_SIZE,          // 2,
// };

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, ARP_ENTRIES_MAX_SIZE);  // 2,
  __type(key, u32);                           // IPv4 address
  __type(value, struct s_arp_mapping);        // <IP Address, MAC address>
} m_arp_table SEC(".maps");

/*---------------------------------------------------------------------------------------------------------------*/
// struct bpf_map_def SEC("maps") m_enforcing_qos = {
//     .type        = BPF_MAP_TYPE_HASH,
//     .key_size    = sizeof(u32),  // far_id
//     .value_size  = sizeof(u32),  // enforcing_qos
//     .max_entries = MAX_FAR_PROGRAMS,
// };

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_FAR_PROGRAMS);  // 1,
  __type(key, u32);
  __type(value, u32);
} m_enforcing_qos SEC(".maps");

/*---------------------------------------------------------------------------------------------------------------*/
// BPF_ANNOTATE_KV_PAIR(m_far, u8, pfcp_far_t_);
// BPF_ANNOTATE_KV_PAIR(m_redirect_interfaces, u32, u32);
// BPF_ANNOTATE_KV_PAIR(m_arp_table, u32, ??);

#endif  // __FAR_MAPS_H__
