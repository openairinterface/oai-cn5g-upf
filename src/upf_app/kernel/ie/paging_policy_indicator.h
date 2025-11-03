#ifndef __PAGING_POLICY_INDICATOR_H__
#define __PAGING_POLICY_INDICATOR_H__

#include <types.h>
#include <ie/ie_base.h>

// 8.2.116 Paging Policy Indicator (PPI)
typedef struct paging_policy_indicator_s {
  u8 spare : 4;
  u8 ppi_value : 4;
} paging_policy_indicator_t;

#endif  // __PAGING_POLICY_INDICATOR_H__