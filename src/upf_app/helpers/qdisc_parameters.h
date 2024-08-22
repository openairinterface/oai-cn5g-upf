
#ifndef __QDISC_PARAMETERS_H__
#define __QDISC_PARAMETERS_H__

#include <types.h>

struct qdiscRootParams {
  const char* scheduler;
  // uint32_t rate;
  // uint32_t ceil;
  // uint32_t burst;
  // uint32_t cburst;
  uint64_t quantum;
  uint64_t defaultClass;
  // int level;
};

struct classParams {
  const char* scheduler;
  uint64_t rate;
  uint64_t ceil;
  uint64_t burst;
  uint64_t cburst;
  uint64_t priority;
};

struct classPosition {
  uint64_t parentMaj;
  uint64_t parentMin;
  uint64_t childMaj;
  uint64_t childMin;
};

#endif  //__QDISC_PARAMETERS_H__