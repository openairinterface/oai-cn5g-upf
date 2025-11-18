#if !defined(IE_FTEID_H)
#define IE_FTEID_H

#include "linux/custom_types.h"
#include "ie/ie_base.h"
#include "ie/teid.h"

//-------------------------------------
// 8.2.3 F-TEID
typedef struct fteid {
  ie_base_t base;
  u8 chid : 1;
  u8 ch : 1;
  u8 v4 : 1;
  u8 v6 : 1;
  teid_t teid;
  u32 ipv4_address;
  u8 ipv6_address[16];
  u8 choose_id;
} _fteid_t;

#endif  // IE_FTEID_H
