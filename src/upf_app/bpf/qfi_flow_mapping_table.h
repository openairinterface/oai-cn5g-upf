#ifndef __QFI_FLOW_MAPPING_TABLE_H__
#define __QFI_FLOW_MAPPING_TABLE_H__

#include <types.h>
#include <stdint.h>

struct s_qfi_parameters {
  const char* resource_type;
  u32 qos;
  u8 qfi;
};

#endif  // __QFI_FLOW_MAPPING_TABLE_H__