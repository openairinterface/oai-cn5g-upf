#ifndef __FILTER_KEY_H__
#define __FILTER_KEY_H__

#include <types.h>

struct filter_key {
  u32 src_ip;
  u32 dst_ip;
  u8 protocol;
  u16 dst_port;
  u32 tos;
};

#endif  // __FILTER_KEY_H__
