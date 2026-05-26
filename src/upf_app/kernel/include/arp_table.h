#ifndef __ARP_TABLE_H__
#define __ARP_TABLE_H__

#include "linux/custom_types.h"

struct arp_entry {
  u8 mac_address[6];
  u32 ipv4_address;
};

#endif  // __ARP_TABLE_H__