
#ifndef __STANDARDIZED_5QI_H__
#define __STANDARDIZED_5QI_H__

#include <types.h>
#include <stdint.h>

typedef enum { GBR, NON_GBR, DELAY_CRITICAL_GBR } e_resource_type;

struct QosFlowParams {
  e_resource_type resource_type;
  u32 default_priority_level;
  u32 packet_delay_budget;
  double packet_error_rate;
  double default_maximum_data_burst_volume;
  u32 default_averaging_window;
};

#endif  //__STANDARDIZED_5QI_H__