#ifndef __PFCP_SESSION_LOOKUP_MAPS_H__
#define __PFCP_SESSION_LOOKUP_MAPS_H__

#include "linux/custom_types.h"
#include "ie/group_ie/create_pdr.h"
#include "ie/teid.h"
#include "pfcp/pfcp_pdr.h"
#include "pfcp/pfcp_far.h"
#include "arp_table.h"
//#include "pfcp/pfcp_session.h"
#include "rules_matching_pdr.h"
#include "interfaces.h"
#include "session_id.h"

#include <linux/bpf.h>
#include <stdint.h>

#define MAX_PDRS_PER_SESSION 32

const volatile int MAX_UPF_INTERFACES SEC(".rodata");
const volatile int MAX_UPF_REDIRECT_INTERFACES SEC(".rodata");
const volatile int MAX_PDU_SESSIONS SEC(".rodata");
const volatile int MAX_PDRS_PER_PDU_SESSION SEC(".rodata");
const volatile int MAX_SDF_FILTERS_PER_PDU_SESSION SEC(".rodata");
const volatile int MAX_ARP_ENTRIES SEC(".rodata");
const volatile int MAX_QOS_ENABLING SEC(".rodata");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* MAX_UPF_INTERFACES */
  __type(key, reference_point_t);
  __type(value, struct interface_config);
} upf_interface_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);           /* max_sdf_filters_per_pdu_session */
  __type(key, struct session_qfi);  // <qfi, seid>
  __type(value, struct sdf_filtr);
} sdf_filters_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);            /* MAX_PDU_SESSIONS */
  __type(key, u32);                  // ue_ip_address
  __type(value, struct session_id);  // < teid_ul, teid_dl, seid >
} session_by_ue_ip_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  /* max_pdrs_per_pdu_session */  // should be this: MAX_PDU_SESSIONS
  __type(key, u64);               // seid
  __type(value, pfcp_pdr_t[MAX_PDRS_PER_SESSION]);  // should be this:
                                                    // MAX_PDRS_PER_PDU_SESSION
} pdrs_per_session_map SEC(".maps");                // m_session_pdrs

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* max_pdrs_per_pdu_session * max_pdu_session */
  __type(key, struct pdrs_per_session);   // < pdr_id, seid >
  __type(value, struct rules_match_pdr);  // < FAR, QER, /* MAR, BAR, URR */ >
} rules_match_pdr_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* max_qos_enabling = max_pdu_session */
  __type(key, u64);       // seid
  __type(value, u32);     // Value type (0 for false, 1 for true)
} session_qos_enabled_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_DEVMAP);
  __uint(max_entries, 1);
  __type(key, u32);    // id
  __type(value, u32);  // tx port
} redirect_interfaces_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, u32);                 // IPv4 address
  __type(value, struct arp_entry);  // <IP Address, MAC address>
} arp_table_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, u32);    // hash_framed_routing_key
  __type(value, u32);  // ue_ip
} m_framed_route_mapping SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);  // Single entry for the flag
  __type(key, u8);         // Key is a constant, e.g., 0
  __type(value, u8);       // Value indicates if framed routing is enabled
} framed_routing_flag SEC(".maps");

#endif  // __PFCP_SESSION_LOOKUP_MAPS_H__
