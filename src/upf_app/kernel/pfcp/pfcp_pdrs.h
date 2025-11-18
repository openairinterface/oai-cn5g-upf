#ifndef __PFCP_PDRS_H__
#define __PFCP_PDRS_H__

#include "pfcp/pfcp_pdr.h"

#define PDRS_MAX_SIZE 10000

typedef struct pfcp_pdrs {
  u32 pdrs_counter;
  pfcp_pdr_t pdrs[PDRS_MAX_SIZE];

} pfcp_pdrs_t;

#endif  // __PFCP_PDRS_H__
