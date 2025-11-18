#ifndef __TRANSPORT_LEVEL_MARKING_H__
#define __TRANSPORT_LEVEL_MARKING_H__

#include "linux/custom_types.h"
#include "ie/ie_base.h"

//-------------------------------------
// 8.2.12 Transport Level Marking
typedef struct transport_level_marking {
  ie_base_t base;
  s8 transport_level_marking[2];  // 2 octets
} transport_level_marking_t;

#endif  // __TRANSPORT_LEVEL_MARKING_H__