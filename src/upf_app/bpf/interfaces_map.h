#ifndef __INTERFACES_MAP_H__
#define __INTERFACES_MAP_H__

#include <bpf_helpers.h>
#include <linux/bpf.h>
#include <types.h>
#include "interfaces.h"

#define INTERFACE_ENTRIES_MAX 12


/*****************************************************************************************************************/
struct bpf_map_def SEC("maps") m_iface = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(reference_point),
    .value_size  = sizeof(struct interface),
    .max_entries = INTERFACE_ENTRIES_MAX, //6,
};

// BPF_ANNOTATE_KV_PAIR(m_next_rule_prog_index, struct next_rule_prog_index_key,
// u32);

#endif  // __INTERFACES_MAP_H__