#ifndef __NEXT_PROG_RULE_MAP_H__
#define __NEXT_PROG_RULE_MAP_H__

#include <bpf_helpers.h>
#include <linux/bpf.h>
#include <types.h>

#define MAX_LENGTH 5000  // 10

/*
 *   +------------------------------------------------------+
 *   |                   m_next_rule_prog                   |
 *   +--------------------------+---------------------------+
 *   |        Key               |                    Value  |
 *   +--------------------------+---------------------------+
 *   |                          |                           |
 *   |    u32 FAR_ID            |  u32 FAR File Descriptor  |
 *   |                          |                           |
 *   +--------------------------+---------------------------+
 */
struct bpf_map_def SEC("maps") m_next_rule_prog = {
    .type        = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size    = sizeof(u32),
    .value_size  = sizeof(s32),
    .max_entries = MAX_LENGTH,  // 10,
};

// BPF_ANNOTATE_KV_PAIR(m_next_rule_prog, u32, s32);

#endif  // __NEXT_PROG_RULE_MAP_H__
