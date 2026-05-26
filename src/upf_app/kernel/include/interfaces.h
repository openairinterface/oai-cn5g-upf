#ifndef __INTERFACES_H__
#define __INTERFACES_H__

#include "linux/custom_types.h"

typedef enum {
  N3_INTERFACE,
  N6_INTERFACE,
  N4_INTERFACE,
  N9_INTERFACE,
  N19_INTERFACE
} reference_point_t;

struct interface_config {
  u32 ipv4_address;
  u32 port;
  const char* if_name;
};

#endif  // __INTERFACES_H__