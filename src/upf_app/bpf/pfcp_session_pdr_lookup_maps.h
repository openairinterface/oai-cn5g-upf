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

/*****************************************************************************************************************/
struct bpf_map_def SEC("maps") m_fars = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(u32),          // teid
    .value_size  = sizeof(pfcp_far_t_),  // list of pdr
    .max_entries = FAR_ENTRIES_MAX_SIZE,
};

/*****************************************************************************************************************/
struct bpf_map_def SEC("maps") m_redirect_interfaces = {
    .type        = BPF_MAP_TYPE_DEVMAP,
    .key_size    = sizeof(u32),  // id
    .value_size  = sizeof(u32),  // tx port
    .max_entries = MAX_LENGTH,   // 10,
};

/*****************************************************************************************************************/
// Uplink map.
// TODO: Store multiple PDR.
struct bpf_map_def SEC("maps") m_teid_pdr = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(teid_t_),       // teid
    .value_size  = sizeof(pfcp_pdr_t_),   // assuming only one PDR
    .max_entries = PDR_ENTRIES_MAX_SIZE,  // 10,
};

/*****************************************************************************************************************/
// Downlink map.
// TODO: Store multiple PDR.
struct bpf_map_def SEC("maps") m_ueip_pdr = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(u32),           // UE IP address
    .value_size  = sizeof(pfcp_pdr_t_),   // assuming only one PDR
    .max_entries = PDR_ENTRIES_MAX_SIZE,  // 10,
};

/*****************************************************************************************************************/
// Static ARP Table. Used to get the MAC address of the next hop.
// TODO:  Pin this maps. It does not depend on the session program
struct bpf_map_def SEC("maps") m_arp_table = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(u32),           // IPv4 address
    .value_size  = 6,                     // MAC address
    .max_entries = ARP_ENTRIES_MAX_SIZE,  // 2,
};
#endif  // __PFCP_SESSION_PDR_LOOKUP_MAPS_H__
