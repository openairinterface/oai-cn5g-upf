#ifndef __QFI_FLOW_MAPPING_TABLE_H__
#define __QFI_FLOW_MAPPING_TABLE_H__

#include <types.h>
#include <stdint.h>

typedef enum { DELAY_CRITICAL_GBR, GBR, NON_GBR } e_resource_type;

struct s_qfi_parameters {
  e_resource_type resource_type;
  u8 qfi;
  u32 qos;
};

#endif  // __QFI_FLOW_MAPPING_TABLE_H__