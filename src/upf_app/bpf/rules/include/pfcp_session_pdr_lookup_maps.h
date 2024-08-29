#ifndef __PFCP_SESSION_PDR_LOOKUP_MAPS_H__
#define __PFCP_SESSION_PDR_LOOKUP_MAPS_H__

#include <linux/bpf.h>
#include <types.h>
#include <pfcp/pfcp_pdr.h>
#include <pfcp/pfcp_far.h>
#include <ie/fteid.h>
#include <ie/fseid.h>

#define MAX_LENGTH 5000            // 10
#define PDR_ENTRIES_MAX_SIZE 5000  // 10
#define FAR_ENTRIES_MAX_SIZE 5000  // 10
#define ARP_ENTRIES_MAX_SIZE 12

/*---------------------------------------------------------------------------------------------------------------*/
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, FAR_ENTRIES_MAX_SIZE);
  __type(key, u32);            // teid
  __type(value, pfcp_far_t_);  // list of pdr
} m_fars SEC(".maps");

/*---------------------------------------------------------------------------------------------------------------*/
struct {
  __uint(type, BPF_MAP_TYPE_DEVMAP);
  __uint(max_entries, MAX_LENGTH);  // 10,
  __type(key, u32);                 // id
  __type(value, u32);               // tx port
} m_redirect_interfaces SEC(".maps");

/*---------------------------------------------------------------------------------------------------------------*/
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, PDR_ENTRIES_MAX_SIZE);  // 10,
  __type(key, teid_t_);                       // teid
  __type(value, pfcp_pdr_t_);                 // assuming only one PDR
} m_teid_pdr SEC(".maps");

/*---------------------------------------------------------------------------------------------------------------*/
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, PDR_ENTRIES_MAX_SIZE);  // 10,
  __type(key, u32);                           // UE IP address
  __type(value, pfcp_pdr_t_);                 // assuming only one PDR
} m_ueip_pdr SEC(".maps");

/*---------------------------------------------------------------------------------------------------------------*/
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, ARP_ENTRIES_MAX_SIZE);  // 2,
  __type(key, u32);                           // IPv4 address
  __type(value, unsigned char[8]);            // MAC address
} m_arp_table SEC(".maps");

#endif  // __PFCP_SESSION_PDR_LOOKUP_MAPS_H__
