#ifndef __TRAFFIC_H__
#define __TRAFFIC_H__

#include <types.h>
#include <stdint.h>

// u16 dscp_dl_or_qfi_ul; TODO: add this field when it works
// u16 src_port;
// u16 dest_port;
// Add other relevant parameters as needed

struct s_traffic {
  u32 src_ip;
  u8 protocol;
  u32 dest_ip;
};

#endif  // __TRAFFIC_H__