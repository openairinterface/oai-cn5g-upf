
#ifndef __QOS_FLOW_H__
#define __QOS_FLOW_H__

#include <types.h>

struct s_fiveQosFlow {
  uint8_t gate;
  uint64_t mbr;
  uint64_t gbr;
  uint8_t qfi;
};

#endif  //__QOS_FLOW_H__