#ifndef __TRAFFIC_H__
#define __TRAFFIC_H__

#include <types.h>
#include <stdint.h>

struct s_traffic {
  u32 src_ip;
  u32 dest_ip;
  u16 src_port;
  u16 dest_port;
  u8 dscp;
  u8 protocol;
  u32 teid_ul;
  // Add other relevant parameters as needed
};

#endif  // __TRAFFIC_H__