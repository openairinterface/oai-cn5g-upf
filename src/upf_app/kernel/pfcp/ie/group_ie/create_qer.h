/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_CREATE_QER_H
#define _PFCP_CREATE_QER_H

#include "ie/ie_base.h"
#include "ie/qer_id.h"
#include "ie/qer_correlation_id.h"
#include "ie/gate_status.h"
#include "ie/mbr.h"
#include "ie/gbr.h"
#include "ie/qfi.h"
#include "ie/reflective_qos.h"
#include "ie/paging_policy_indicator.h"

/**
 * struct create_qer - Create QoS Enforcement Rule IE
 * @base: Common IE header
 * @qer_id: QER identifier
 * @qer_correlation_id: QER correlation identifier
 * @gate_status: Gate status for UL/DL
 * @maximum_bitrate: Maximum Bit Rate (MBR)
 * @guaranteed_bitrate: Guaranteed Bit Rate (GBR)
 * @qos_flow_identifier: QoS Flow Identifier (QFI)
 * @reflective_qos: Reflective QoS activation
 * @paging_policy_indicator: Paging policy indicator
 *
 * Provisions a QoS Enforcement Rule for rate limiting and gating.
 */
struct create_qer {
  // struct ie_base base;
  struct qer_id qer_id;
  struct qer_correlation_id qer_correlation_id;
  struct gate_status gate_status;
  struct mbr maximum_bitrate;
  struct gbr guaranteed_bitrate;
  struct qfi qos_flow_identifier;
  struct rqi reflective_qos;
  struct paging_policy_indicator paging_policy_indicator;
} __attribute__((packed));

#endif /* _PFCP_CREATE_QER_H */
