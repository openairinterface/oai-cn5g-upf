#ifndef __MAXIMUM_BITRATE_H__
#define __MAXIMUM_BITRATE_H__

#include <types.h>
#include <ie/ie_base.h>

// 8.2.8 MBR
typedef struct mbr_s {
  u64 ul_mbr;
  u64 dl_mbr;
} mbr_t;

#endif  // __MAXIMUM_BITRATE_H__