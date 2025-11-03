#ifndef __GUARANTEED_BITRATE_H__
#define __GUARANTEED_BITRATE_H__

#include <types.h>
#include <ie/ie_base.h>

// 8.2.9 GBR
typedef struct gbr_s {
  u64 ul_gbr;
  u64 dl_gbr;
} gbr_t;

#endif  // __GUARANTEED_BITRATE_H__