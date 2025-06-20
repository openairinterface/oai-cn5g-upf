#ifndef __GATE_STATUS_H__
#define __GATE_STATUS_H__

#include <types.h>
#include <ie/ie_base.h>

//  8.2.7 Gate Status
enum gate_status_e {
  /* Request / Initial message */
  OPEN   = 0,
  CLOSED = 1
};

typedef struct gate_status_s {
  u8 ul_gate : 2;
  u8 dl_gate : 2;
} gate_status_t;

#endif  // __GATE_STATUS_H__