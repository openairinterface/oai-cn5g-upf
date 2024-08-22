#ifndef __ARP_TABLE_MAP_H__
#define __ARP_TABLE_MAP_H__

#include <types.h>
//#include <stdint.h>

struct s_arp_mapping {
  uint8_t mac_address[6];
  uint32_t ipv4_address;
};

#endif  // __ARP_TABLE_MAP_H__