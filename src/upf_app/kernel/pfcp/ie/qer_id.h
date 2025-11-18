#ifndef __QER_ID_H__
#define __QER_ID_H__

#include "linux/custom_types.h"
#include "ie/ie_base.h"

//-------------------------------------
// 8.2.75 QER ID
typedef struct qer_id {
  ie_base_t base;
  u32 qer_id;
} qer_id_t;

#endif  // __QER_ID_H__