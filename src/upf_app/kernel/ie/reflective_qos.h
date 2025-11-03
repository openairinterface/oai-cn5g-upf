#ifndef __REFLECTIVE_QOS_H__
#define __REFLECTIVE_QOS_H__

#include <types.h>
#include <ie/ie_base.h>

/// 8.2.88 RQI
typedef struct rqi_s {
  u8 spare : 7;
  u8 rqi : 1;
} rqi_t;
#endif  // __REFLECTIVE_QOS_H__