#ifndef __PFCP_SESSION_LOOKUP_MAPS_H__
#define __PFCP_SESSION_LOOKUP_MAPS_H__

#include <ie/group_ie/create_pdr.h>
#include <pfcp/pfcp_pdr.h>
#include <pfcp/pfcp_session.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <ie/teid.h>
#include <next_prog_rule_map.h>
#include <next_prog_rule_key.h>
#include "interfaces.h"
#include "session_id.h"

#define MAX_LENGTH 5000  // 10
#define INTERFACE_ENTRIES_MAX 12
#define MAX_UEs 100000

/*---------------------------------------------------------------------------------------------------------------*/
struct {
  __uint(
      type,
      BPF_MAP_TYPE_PROG_ARRAY);  //!< Must have the key and value with 4 bytes
  __type(key, teid_t_);          //!< program identifier.
  __type(value, s32);            //!< program which represents the session.
  // TODO: Check how the management works. The size should be equal
  // to the maximum number of sessions.
  __uint(max_entries, MAX_LENGTH);  // 10000,  //!< TODO: Is it enought?
} m_teid_session SEC(".maps");

/*---------------------------------------------------------------------------------------------------------------*/
struct {
  __uint(
      type,
      BPF_MAP_TYPE_PROG_ARRAY);  //!< Must have the key and value with 4 bytes
  __type(key, u32);              //!< program identifier.
  __type(value, s32);            //!< program which represents the session.
  // TODO Check how the management works. The size should be equal
  // to the maximum number of sessions.
  __uint(max_entries, MAX_UEs);  //!< TODO: Is it enought?
} m_ueip_session SEC(".maps");

/*---------------------------------------------------------------------------------------------------------------*/
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_UEs);
  __type(key, u32);    //!< UE IP
  __type(value, u32);  //!< PDR
} m_ue_ip_pdr SEC(".maps");

/*---------------------------------------------------------------------------------------------------------------*/
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_LENGTH);  // 10,
  __type(key, struct next_rule_prog_index_key);
  __type(value, u32);
} m_next_rule_prog_index SEC(".maps");

/*---------------------------------------------------------------------------------------------------------------*/
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, INTERFACE_ENTRIES_MAX);  // 6,
  __type(key, e_reference_point);
  __type(value, struct s_interface);
} m_upf_interfaces SEC(".maps");

/*---------------------------------------------------------------------------------------------------------------*/
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_LENGTH);
  __type(key, u32);                  // ue_ip_address
  __type(value, struct session_id);  // < teid_ul, teid_dl, seid >
} m_session_mapping SEC(".maps");

/*---------------------------------------------------------------------------------------------------------------*/

#endif  // __PFCP_SESSION_LOOKUP_MAPS_H__
