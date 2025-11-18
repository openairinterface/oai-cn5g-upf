#if !defined(IE_APPLICATION_ID_H)
#define IE_APPLICATION_ID_H

#include "linux/custom_types.h"
#include "ie/ie_base.h"

//-------------------------------------
//  8.2.6 Application ID
typedef struct application_id {
  ie_base_t base;
  // TODO string size is not 10.
  u8 application_id[10];
} application_id_t;

#endif  // IE_APPLICATION_ID_H
