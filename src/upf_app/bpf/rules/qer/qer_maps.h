#ifndef __QER_MAPS_H__
#define __QER_MAPS_H__

#include <bpf_helpers.h>
#include <linux/bpf.h>
#include <types.h>
#include "filter_key.h"
#include "qos_flow.h"

#define QFI_MAX_ENTRIES 5000
#define FIVE_QI_MAX_ENTRIES 100
#define QOS_FLOWS_MAX_ENTRIES 100
#define MAX_INTERFACES 10

/*---------------------------------------------------------------------------------------------------------------*/
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, QFI_MAX_ENTRIES);  // 10,
  __type(key, struct filter_key);
  __type(value, struct session_qfi);
} m_sdf_filter SEC(".maps");

/*---------------------------------------------------------------------------------------------------------------*/
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, QOS_FLOWS_MAX_ENTRIES);
  __type(key, u32);
  __type(value, struct s_fiveQosFlow);
} m_qos_flow SEC(".maps");

/*---------------------------------------------------------------------------------------------------------------*/
struct {
  __uint(type, BPF_MAP_TYPE_DEVMAP);
  __uint(max_entries, MAX_INTERFACES);
  __type(key, u32);
  __type(value, u32);
} m_egress_ifindex SEC(".maps");

#endif  // __QER_MAPS_H__