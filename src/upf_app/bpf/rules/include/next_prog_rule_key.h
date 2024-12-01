#ifndef __NEXT_PROG_RULE_KEY_H__
#define __NEXT_PROG_RULE_KEY_H__

#include <ie/teid.h>
#include <types.h>

struct next_rule_prog_index_key {
  teid_t_ teid;
  u8 source_value;
  u32 ipv4_address;
};

struct next_rule_eth_prog_index_key {
  teid_t_ teid;
  u8 source_value;
  u16 ethertype;
  // TODO [ETH-PDU] handle keys with MAC Address
};

struct next_rule_eth_prog_index_value {
  u32 prog_id;
  u32 teid_dl;
};

#endif  // __NEXT_PROG_RULE_KEY_H__
