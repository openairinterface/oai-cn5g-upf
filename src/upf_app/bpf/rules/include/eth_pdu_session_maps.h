#ifndef __ETH_PDU_SESSION_MAPS_H__
#define __ETH_PDU_SESSION_MAPS_H__

#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <mac_pdu_session_key.h>

#define MAX_LENGTH 5000  // 10
#define INTERFACE_ENTRIES_MAX 12
#define MAX_UEs 100000
#define MAX_INTERFACES 10

/*---------------------------------------------------------------------------------------------------------------*/
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_LENGTH);  // 10,
  __type(key, u8[ETH_ALEN]);
  __type(value, struct mac_pdu_session_value);
  __uint(pinning, 1);
} m_mac_pdu_session SEC(".maps");

/*---------------------------------------------------------------------------------------------------------------*/
struct {
  __uint(type, BPF_MAP_TYPE_DEVMAP);
  __uint(max_entries, MAX_INTERFACES);  // 10,
  __type(key, u32);                     // id
  __type(value, u32);                   // tx port
} m_egress_ifindex SEC(".maps");

#endif  // __ETH_PDU_SESSION_MAPS_H__