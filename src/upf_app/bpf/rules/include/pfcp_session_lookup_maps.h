#ifndef __PFCP_SESSION_LOOKUP_MAPS_H__
#define __PFCP_SESSION_LOOKUP_MAPS_H__

#include <bpf_helpers.h>
#include <ie/group_ie/create_pdr.h>
#include <pfcp/pfcp_pdr.h>
#include <pfcp/pfcp_far.h>
#include <pfcp/pfcp_session.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <ie/teid.h>
#include <mac_pdu_session_key.h>
#include <rules_matching_pdr.h>
#include "interfaces.h"
#include "session_id.h"

#define MAX_PDRS_PER_SESSION 32
#define MAX_ETH_PDU_SESSIONS 500

const volatile int max_upf_interfaces SEC(".rodata");
const volatile int max_upf_redirect_interfaces SEC(".rodata");
const volatile int max_pdu_session SEC(".rodata");
const volatile int max_pdrs_per_pdu_session SEC(".rodata");
const volatile int max_sdf_filters_per_pdu_session SEC(".rodata");
const volatile int max_arp_entries SEC(".rodata");
const volatile int max_qos_enabling SEC(".rodata");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* max_upf_interfaces */
  __type(key, e_reference_point);
  __type(value, struct s_interface);
} m_upf_interfaces SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);           /* max_sdf_filters_per_pdu_session */
  __type(key, struct session_qfi);  // <qfi, seid>
  __type(value, struct sdf_filtr);
} m_sdf_filter SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);            /* max_pdu_session */
  __type(key, u32);                  // ue_ip_address
  __type(value, struct session_id);  // < teid_ul, teid_dl, seid >
} m_session_mapping SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* max_pdrs_per_pdu_session */
  __type(key, u64);       // seid
  __type(value, pfcp_pdr_t_[MAX_PDRS_PER_SESSION]);
} m_session_pdrs SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* max_pdrs_per_pdu_session * max_pdu_session */
  __type(key, struct pdrs_per_session);   // < pdr_id, seid >
  __type(value, struct rules_match_pdr);  // < FAR, QER, /* MAR, BAR, URR */ >
} m_rules_match_pdr SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1); /* max_qos_enabling = max_pdu_session */
  __type(key, u64);       // seid
  __type(value, u32);     // Value type (0 for false, 1 for true)
} m_qos_enabling SEC(".maps");

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

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(
      max_entries,
      MAX_ETH_PDU_SESSIONS);  // 500 // TODO: check from 3gpp standards
  __type(key, u8[ETH_ALEN]);
  __type(value, struct mac_pdu_session_value);
  __uint(pinning, 1);
} m_mac_pdu_session SEC(".maps");

#endif  // __PFCP_SESSION_LOOKUP_MAPS_H__
