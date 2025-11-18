#ifndef __MAXIMUM_BITRATE_H__
#define __MAXIMUM_BITRATE_H__

#include "linux/custom_types.h"

// 8.2.8 MBR
typedef struct mbr {
  u64 ul_mbr;
  u64 dl_mbr;
} mbr_t;

#endif  // __MAXIMUM_BITRATE_H__