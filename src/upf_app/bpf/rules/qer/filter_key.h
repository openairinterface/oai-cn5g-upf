#ifndef __FILTER_KEY_H__
#define __FILTER_KEY_H__

#include <types.h>

#define GET_TC_CLASSID(seid, qfi)                                              \
  (u32)((((u32)(seid) *256) + ((u8)(qfi) *251 % 256)))

struct filter_key {
  u32 src_ip;
  u32 dst_ip;
  u8 protocol;
  // TODO [QOS]: Support for src port
  // u16 src_port;
  u16 dst_port;
  u32 tos;
};

struct session_qfi {
  u64 seid;
  u8 qfi;
};

#endif  // __FILTER_KEY_H__
