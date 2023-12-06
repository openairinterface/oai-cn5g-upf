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
//#include "traffic_classification.h"
// #include "session_mapping.h"
// #include "ue_teid_qfi_matching.h"
// #include "qfi_flow_mapping_table.h"

#define MAX_LENGTH 5000  // 10
#define INTERFACE_ENTRIES_MAX 12
#define MAX_UEs 100000

/*****************************************************************************************************************/
// Maps TEID to PFCP_Session_PDR_LookupProgram

struct bpf_map_def SEC("maps") m_teid_session = {
    .type =
        BPF_MAP_TYPE_PROG_ARRAY,  //!< Must have the key and value with 4 bytes
    .key_size   = sizeof(teid_t_),  //!< program identifier.
    .value_size = sizeof(s32),      //!< program which represents the session.
    // TODO: Check how the management works. The size should be equal
    // to the maximum number of sessions.
    .max_entries = MAX_LENGTH,  // 10000,  //!< TODO: Is it enought?
};

/*****************************************************************************************************************/
// Maps UE IPv4 address to PFCP_Session_PDR_LookupProgram
// FIXME: Select a primary key. We could use a hash value of the IP as a key.

struct bpf_map_def SEC("maps") m_ueip_session = {
    .type =
        BPF_MAP_TYPE_PROG_ARRAY,  //!< Must have the key and value with 4 bytes
    .key_size   = sizeof(u32),    //!< program identifier.
    .value_size = sizeof(s32),    //!< program which represents the session.
    // TODO Check how the management works. The size should be equal
    // to the maximum number of sessions.
    .max_entries = MAX_UEs,  //!< TODO: Is it enought?
};

/*****************************************************************************************************************/

struct bpf_map_def SEC("maps") m_ue_ip_pdr = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(u32),  //!< UE IP
    .value_size  = sizeof(u32),  //!< PDR
    .max_entries = MAX_UEs,
};

/*****************************************************************************************************************/

struct bpf_map_def SEC("maps") m_next_rule_prog_index = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(struct next_rule_prog_index_key),
    .value_size  = sizeof(u32),
    .max_entries = MAX_LENGTH,  // 10,
};

/*****************************************************************************************************************/

struct bpf_map_def SEC("maps") m_upf_interfaces = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(e_reference_point),
    .value_size  = sizeof(struct s_interface),
    .max_entries = INTERFACE_ENTRIES_MAX,  // 6,
};

/*****************************************************************************************************************/

struct bpf_map_def SEC("maps") m_session_mapping = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(u32),  // ue_ip_address
    .value_size  = sizeof(u32),  // teid_dl
    .max_entries = MAX_LENGTH,
};

/*****************************************************************************************************************/

// struct bpf_map_def SEC("maps") m_traffic_classification = {
//     .type        = BPF_MAP_TYPE_HASH,
//     .key_size    = sizeof(struct s_traffic),
//     .value_size  = sizeof(u32),  // teid_dl
//     .max_entries = MAX_LENGTH,
// };

/*****************************************************************************************************************/

// struct bpf_map_def SEC("maps") m_ue_qfi_teid = {
//     .type        = BPF_MAP_TYPE_HASH,
//     .key_size    = sizeof(struct s_ue_qfi),
//     .value_size  = sizeof(u32),  // teid_ul
//     .max_entries = MAX_LENGTH,
// };

/*****************************************************************************************************************/

// struct bpf_map_def SEC("maps") m_qos_flow_map = {
//     .type        = BPF_MAP_TYPE_HASH,
//     .key_size    = sizeof(u8),  // dscp
//     .value_size  = sizeof(struct s_qfi_parameters),
//     .max_entries = MAX_LENGTH,
// };

#endif  // __PFCP_SESSION_LOOKUP_MAPS_H__
