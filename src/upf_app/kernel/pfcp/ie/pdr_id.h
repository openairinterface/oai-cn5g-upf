#ifndef __PDR_ID_H__
#define __PDR_ID_H__

#include "linux/custom_types.h"
#include "ie/ie_base.h"

//-------------------------------------
// 8.2.36 Packet Detection Rule ID (PDR ID)
typedef struct pdr_id {
  ie_base_t base;
  u16 rule_id;
} pdr_id_t;

#endif  // __PDR_ID_H__