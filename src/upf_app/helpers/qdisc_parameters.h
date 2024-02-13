
#ifndef __QDISC_PARAMETERS_H__
#define __QDISC_PARAMETERS_H__

#include <types.h>

struct qdisc_root_params {
  const char *scheduler;
  //uint32_t rate;
  // uint32_t ceil;
  // uint32_t burst;
  // uint32_t cburst;
  uint32_t quantum;
  uint32_t defaultClass;
  // int level;
};


struct class_params {
  const char *scheduler;
  uint32_t rate;
  uint32_t ceil;
  uint32_t burst;
  uint32_t cburst;
  uint32_t priority;
};


struct class_position {
  uint32_t parentMaj;
  uint32_t parentMin;
  uint32_t childMaj;
  uint32_t childMin;
  };



#endif //__QDISC_PARAMETERS_H__