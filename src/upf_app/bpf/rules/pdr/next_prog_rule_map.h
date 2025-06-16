#ifndef __NEXT_PROG_RULE_MAP_H__
#define __NEXT_PROG_RULE_MAP_H__

#include <bpf_helpers.h>
#include <linux/bpf.h>
#include <types.h>
#include <pfcp/pfcp_far.h>

#define MAX_LENGTH 10000

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

struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, MAX_LENGTH);
  __type(key, u32);
  __type(value, s32);
} m_next_rule_prog SEC(".maps");

// BPF_ANNOTATE_KV_PAIR(m_next_rule_prog, u32, s32);

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_LENGTH);
  __type(key, u32);
  __type(value, pfcp_far_t_);
  __uint(pinning, 1);
} m_far_eth SEC(".maps");

#endif  // __NEXT_PROG_RULE_MAP_H__
