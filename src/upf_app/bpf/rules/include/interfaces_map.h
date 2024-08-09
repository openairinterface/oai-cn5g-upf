#ifndef __INTERFACES_MAP_H__
#define __INTERFACES_MAP_H__

#include <bpf_helpers.h>
#include <linux/bpf.h>
#include <types.h>
#include "interfaces.h"

#define INTERFACE_ENTRIES_MAX 12
#define MAX_INTERFACES 10

/*---------------------------------------------------------------------------------------------------------------*/
struct bpf_map_def SEC("maps") m_redirect_interfaces = {
    .type        = BPF_MAP_TYPE_DEVMAP,
    .key_size    = sizeof(u32),     // id
    .value_size  = sizeof(u32),     // tx port
    .max_entries = MAX_INTERFACES,  // 10,
};

/*---------------------------------------------------------------------------------------------------------------*/
struct bpf_map_def SEC("maps") m_upf_interfaces = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(e_reference_point),
    .value_size  = sizeof(struct s_interface),
    .max_entries = INTERFACE_ENTRIES_MAX,  // 6,
};

// BPF_ANNOTATE_KV_PAIR(m_next_rule_prog_index, struct next_rule_prog_index_key,
// u32);

#endif  // __INTERFACES_MAP_H__