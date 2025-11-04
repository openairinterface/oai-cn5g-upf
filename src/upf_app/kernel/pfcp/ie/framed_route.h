#if !defined(IE_FRAMED_ROUTE_H)
#define IE_FRAMED_ROUTE_H

#include "linux/custom_types.h"
#include "ie/ie_base.h"

//-------------------------------------
// 8.2.109 Framed-Route
typedef struct framed_route {
  ie_base_t_ base;
  u8 framed_route[4];
} framed_route_t_;

#endif  // IE_FRAMED_ROUTING_H
