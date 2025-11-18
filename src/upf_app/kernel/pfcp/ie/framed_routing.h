#if !defined(IE_FRAMED_ROUTING_H)
#define IE_FRAMED_ROUTING_H

#include "linux/custom_types.h"
#include "ie/ie_base.h"

//-------------------------------------
// 8.2.110 Framed-Routing
typedef struct framed_routing {
  ie_base_t base;
  u32 framed_routing;
} framed_routing_t;

#endif  // IE_FRAMED_ROUTING_H
