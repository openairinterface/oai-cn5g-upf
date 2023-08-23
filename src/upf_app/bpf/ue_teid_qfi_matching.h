#ifndef __UE_TEID_QFI_MATCHING_H__
#define __UE_TEID_QFI_MATCHING_H__

#include <types.h>
#include <stdint.h>

struct s_ue_qfi {
  u32 src_ip;
  u8 qfi;
};

#endif  // __UE_TEID_QFI_MATCHING_H__