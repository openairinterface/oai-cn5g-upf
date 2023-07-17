#ifndef __INTERFACES_H__
#define __INTERFACES_H__

#include <types.h>
#include <stdint.h>

typedef enum {
  N3_INTERFACE,
  N6_INTERFACE,
  N4_INTERFACE,
  N9_INTERFACE,
  N19_INTERFACE
} e_reference_point;

struct s_interface {
  u32 ipv4_address;
  u32 port;
  const char* if_name;
};

#endif  // __INTERFACES_H__