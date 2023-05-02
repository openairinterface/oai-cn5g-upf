#ifndef __INTERFACES_H__
#define __INTERFACES_H__

#include <types.h>
#include <atomic>

struct interface {
  std::string if_name;
  u32 ipv4_address;
};

#endif // __INTERFACES_H__
