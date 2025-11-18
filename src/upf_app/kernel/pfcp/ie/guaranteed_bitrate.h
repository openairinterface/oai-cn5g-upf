#ifndef __GUARANTEED_BITRATE_H__
#define __GUARANTEED_BITRATE_H__

#include "linux/custom_types.h"

// 8.2.9 GBR
typedef struct gbr {
  u64 ul_gbr;
  u64 dl_gbr;
} gbr_t;

#endif  // __GUARANTEED_BITRATE_H__