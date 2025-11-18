#ifndef __RULES_MATCHING_PDR_H__
#define __RULES_MATCHING_PDR_H__

#include "linux/custom_types.h"
#include "pfcp/pfcp_far.h"
#include "pfcp/pfcp_qer.h"

struct rules_match_pdr {
  pfcp_far_t far;
  pfcp_qer_t qer;
  // TODO: add other RUles here !
};

struct pdrs_per_session {
  u16 pdr_id;
  u64 seid;
};

#endif  // __RULES_MATCHING_PDR_H__
