
#ifndef __QOS_FLOW_H__
#define __QOS_FLOW_H__

#include <types.h>
/*
typedef enum { OPEN, CLOSE, FUTURE_USE } e_ul_gate_status;
typedef enum { OPEN, CLOSE, FUTURE_USE } e_dl_gate_status;

struct s_gate {
  e_ul_gate_status ul_gate;
  e_dl_gate_status dl_gate;
};
*/

/* Use uint8_t*/
struct s_gate {
  uint8_t ul_gate;
  uint8_t dl_gate;
};

struct s_mbr {
  uint64_t ul_mbr;
  uint64_t dl_mbr;
};

struct s_gbr {
  uint64_t ul_gbr;
  uint64_t dl_gbr;
};

struct s_fiveQosFlow {
  struct s_gate gate;
  struct s_mbr mbr;
  struct s_gbr gbr;
  uint64_t qfi;
};

#endif  //__QOS_FLOW_H__