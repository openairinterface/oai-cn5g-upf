#ifndef __QER_MAPS_H__
#define __QER_MAPS_H__

#include <linux/bpf.h>
#include "linux/custom_types.h"
#include "sdf_filter.h"
//#include "qos_flow.h"

const volatile int max_egress_interfaces SEC(".rodata");
/*---------------------------------------------------------------------------------------------------------------*/
struct {
  __uint(type, BPF_MAP_TYPE_DEVMAP);
  __uint(max_entries, 1);
  __type(key, u32);  // u8?
  __type(value, u32);
} m_egress_ifindex SEC(".maps");

#endif  // __QER_MAPS_H__