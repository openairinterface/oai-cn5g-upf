#ifndef __INTERFACES_MAP_H__
#define __INTERFACES_MAP_H__

#include <bpf_helpers.h>
#include <linux/bpf.h>
#include <types.h>
#include "interfaces.h"

#define INTERFACE_ENTRIES_MAX 12
#define MAX_INTERFACES 10

/*---------------------------------------------------------------------------------------------------------------*/
struct {
  __uint(type, BPF_MAP_TYPE_DEVMAP);
  __uint(max_entries, MAX_INTERFACES);  // 10,
  __type(key, u32);                     // id
  __type(value, u32);                   // tx port
} m_redirect_interfaces SEC(".maps");

/*---------------------------------------------------------------------------------------------------------------*/
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, INTERFACE_ENTRIES_MAX);
  __type(key, e_reference_point);
  __type(value, struct s_interface);  // 6,
} m_upf_interfaces SEC(".maps");

#endif  // __INTERFACES_MAP_H__