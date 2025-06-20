#ifndef __RULES_MATCHING_PDR_H__
#define __RULES_MATCHING_PDR_H__

#include <pfcp/pfcp_far.h>
#include <pfcp/pfcp_qer.h>

struct rules_match_pdr {
  pfcp_far_t_ far;
  pfcp_qer_t_ qer;
  // TODO: add other RUles here !
};

struct pdrs_per_session {
  uint16_t pdr_id;
  uint64_t seid;
};

// struct sdfs_per_session {
//   uint16_t qer_id;
//   uint64_t seid;
// };

#endif  // __RULES_MATCHING_PDR_H__
