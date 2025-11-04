#ifndef __ARP_TABLE_H__
#define __ARP_TABLE_H__

#include "linux/custom_types.h"
//#include <stdint.h>

struct s_arp_mapping {
  u8 mac_address[6];
  u32 ipv4_address;
};

#endif  // __ARP_TABLE_H__