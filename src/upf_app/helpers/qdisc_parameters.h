
#ifndef __QDISC_PARAMETERS_H__
#define __QDISC_PARAMETERS_H__

#include <types.h>

struct qdisc_params {
  const char *scheduler;
  uint32_t rate;
  uint32_t ceil;
  uint32_t rate_buffer;
  uint32_t ceil_buffer;
  uint32_t quantum;
  int level;
};


#endif //__QDISC_PARAMETERS_H__