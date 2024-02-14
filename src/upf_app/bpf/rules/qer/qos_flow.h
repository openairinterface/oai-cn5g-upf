
#ifndef __QOS_FLOW_H__
#define __QOS_FLOW_H__

#include <types.h>

struct  qos_flow{
  uint64_t qfi;
  uint64_t gbr;
  uint64_t mbr;
};

#endif //__QOS_FLOW_H__