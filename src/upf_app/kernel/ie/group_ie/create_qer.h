#if !defined(CREATE_QER_H)
#define CREATE_QER_H

#include <ie/ie_base.h>
#include <ie/qer_id.h>
#include <ie/qer_correlation_id.h>
#include <ie/gate_status.h>
#include <ie/guaranteed_bitrate.h>
#include <ie/maximum_bitrate.h>
#include <ie/qos_flow_identifier.h>
#include <ie/reflective_qos.h>
#include <ie/paging_policy_indicator.h>

//------------------------------------------------------------------------------

// Table 7.5.2.5-1: Create QER IE within PFCP Session Establishment Request
typedef struct create_qer_s {
  qer_id_t_ qer_id;
  qer_correlation_id_t qer_correlation_id;
  gate_status_t gate_status;
  mbr_t maximum_bitrate;
  gbr_t guaranteed_bitrate;
  qfi_t qos_flow_identifier;
  rqi_t reflective_qos;
  paging_policy_indicator_t paging_policy_indicator;
} create_qer_t;

#endif  // CREATE_QER_H
