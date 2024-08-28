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
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, FAR_TAILS_MAX);  // 1,
  __type(key, u8);
  __type(value, pfcp_far_t_);
} m_far SEC(".maps");

/*---------------------------------------------------------------------------------------------------------------*/
struct {
  __uint(type, BPF_MAP_TYPE_DEVMAP);
  __uint(max_entries, MAX_INTERFACES);  // 10,
  __type(key, u32);                     // id
  __type(value, u32);                   // tx port
} m_redirect_interfaces SEC(".maps");

/*---------------------------------------------------------------------------------------------------------------*/
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, ARP_ENTRIES_MAX_SIZE);  // 2,
  __type(key, u32);                           // IPv4 address
  __type(value, struct s_arp_mapping);        // <IP Address, MAC address>
} m_arp_table SEC(".maps");

/*---------------------------------------------------------------------------------------------------------------*/
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_FAR_PROGRAMS);  // 1,
  __type(key, u32);
  __type(value, u32);
} m_enforcing_qos SEC(".maps");

/*---------------------------------------------------------------------------------------------------------------*/

#endif  // __FAR_MAPS_H__
