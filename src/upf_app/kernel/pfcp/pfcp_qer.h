#ifndef __PFCP_QER_H__
#define __PFCP_QER_H__

#include <types.h>
#include <ie/group_ie/create_qer.h>
#include <ie/qer_id.h>
#include <ie/qer_correlation_id.h>
#include <ie/gate_status.h>
#include <ie/guaranteed_bitrate.h>
#include <ie/maximum_bitrate.h>
#include <ie/qos_flow_identifier.h>
#include <ie/reflective_qos.h>
#include <ie/paging_policy_indicator.h>

typedef struct pfcp_qer_s {
  qer_id_t_ qer_id;
  qer_correlation_id_t qer_correlation_id;
  gate_status_t gate_status;
  mbr_t maximum_bitrate;
  gbr_t guaranteed_bitrate;
  qfi_t qos_flow_identifier;
  rqi_t reflective_qos;
  paging_policy_indicator_t paging_policy_indicator;
} pfcp_qer_t_;

#endif  // __PFCP_QER_H__
