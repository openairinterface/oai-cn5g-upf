#ifndef __PFCP_SESSION_ETH__LOOKUP_MAPS_H__
#define __PFCP_SESSION_ETH__LOOKUP_MAPS_H__

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
#define MAX_LENGTH 10000  // 10
#define INTERFACE_ENTRIES_MAX 12
#define MAX_UEs 10000
#define MAX_PDRS_PER_SESSION 32
#define MAX_SDF_FITLER_ENTRIES 1000

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_LENGTH);
  __type(key, u32);  // teid_ul
  __type(
      value, struct eth__session_id);  // < teid_ul, teid_dl, ip_address, seid >
  __uint(pinning, 1);
} m_eth__session_mapping SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_LENGTH);
  __type(key, u64);  // seid
  __type(value, pfcp_pdr_t_[MAX_PDRS_PER_SESSION]);
  __uint(pinning, 1);
} m_eth__session_pdrs SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(
      max_entries,
      MAX_LENGTH);  // max_rules = max_pdrs_per_pdu_session * max_pdu_session
  __type(key, struct pdrs_per_session);   // < pdr_id, seid >
  __type(value, struct rules_match_pdr);  // < FAR, QER, /* MAR, BAR, URR */ >
  __uint(pinning, 1);
} m_eth__rules_match_pdr SEC(".maps");

#endif  // __PFCP_SESSION_ETH__LOOKUP_MAPS_H__