#ifndef __SESSION_MAPPING_H__
#define __SESSION_MAPPING_H__

#include <types.h>
#include <stdint.h>

struct s_session_mapping {
  u32 ue_ip_address;
  u32 teid_ul;
};

#endif  // __SESSION_MAPPING_H__