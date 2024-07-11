
#ifndef __QOS_FLOW_H__
#define __QOS_FLOW_H__

#include <types.h>

typedef enum {
  OPEN,
  CLOSE,
  FUTURE_USE
} e_gate_status;


struct s_mbr {
  uint64_t ul_mbr;
  uint64_t dl_mbr;
};

struct s_gbr {
  uint64_t ul_gbr;
  uint64_t dl_gbr;
};

struct s_fiveQosFlow {
  e_gate_status gate;
  struct s_mbr mbr;
  struct s_gbr gbr;
  uint64_t qfi;
};

#endif  //__QOS_FLOW_H__