#ifndef __QER_MAPS_H__
#define __QER_MAPS_H__

#include <bpf_helpers.h>
#include <linux/bpf.h>
#include <types.h>
#include "sdf_filter.h"
#include "qos_flow.h"

#define QOS_FLOWS_MAX_ENTRIES 10000
#define MAX_INTERFACES 10

/*---------------------------------------------------------------------------------------------------------------*/
struct {
  __uint(type, BPF_MAP_TYPE_DEVMAP);
  __uint(max_entries, MAX_INTERFACES);
  __type(key, u32);  // u8?
  __type(value, u32);
} m_egress_ifindex SEC(".maps");

#endif  // __QER_MAPS_H__