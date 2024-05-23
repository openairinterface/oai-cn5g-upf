#ifndef __INTERFACES_MAP_H__
#define __INTERFACES_MAP_H__

#include <bpf_helpers.h>
#include <linux/bpf.h>
#include <types.h>
#include "interfaces.h"

#define INTERFACE_ENTRIES_MAX 12

/*****************************************************************************************************************/
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, INTERFACE_ENTRIES_MAX);
  __type(key, e_reference_point);
  __type(value, struct s_interface);  // 6,
} m_upf_interfaces SEC(".maps");

// BPF_ANNOTATE_KV_PAIR(m_next_rule_prog_index, struct next_rule_prog_index_key,
// u32);

#endif  // __INTERFACES_MAP_H__