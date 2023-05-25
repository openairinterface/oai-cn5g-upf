#ifndef __NEXT_PROG_RULE_KEY_H__
#define __NEXT_PROG_RULE_KEY_H__

#include <ie/teid.h>
#include <types.h>

struct next_rule_prog_index_key {
  teid_t_ teid;
  u32 ipv4_address;
  u8 source_value;
};

#endif // __NEXT_PROG_RULE_KEY_H__
