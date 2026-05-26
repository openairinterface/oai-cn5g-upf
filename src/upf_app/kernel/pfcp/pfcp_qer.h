/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*
 * PFCP QER (QoS Enforcement Rule)
 * Reference: 3GPP TS 29.244 Section 7.5.2.5
 */

#ifndef _PFCP_QER_H
#define _PFCP_QER_H

#include "ie/qer_id.h"
#include "ie/qer_correlation_id.h"
#include "ie/gate_status.h"
#include "ie/gbr.h"
#include "ie/mbr.h"
#include "ie/qfi.h"
#include "ie/reflective_qos.h"
#include "ie/paging_policy_indicator.h"

/**
 * struct pfcp_qer - QoS Enforcement Rule
 * @qer_id: QER identifier
 * @qer_correlation_id: QER correlation identifier
 * @gate_status: Gate status for UL/DL
 * @maximum_bitrate: Maximum Bit Rate (MBR)
 * @guaranteed_bitrate: Guaranteed Bit Rate (GBR)
 * @qos_flow_identifier: QoS Flow Identifier (QFI)
 * @reflective_qos: Reflective QoS activation
 * @paging_policy_indicator: Paging policy indicator
 *
 * QER structure for QoS enforcement in PFCP sessions.
 */
struct pfcp_qer {
  struct qer_id qer_id;
  struct qer_correlation_id qer_correlation_id;
  struct gate_status gate_status;
  struct mbr maximum_bitrate;
  struct gbr guaranteed_bitrate;
  struct qfi qos_flow_identifier;
  struct rqi reflective_qos;
  struct paging_policy_indicator paging_policy_indicator;
} __attribute__((packed));

#endif /* _PFCP_QER_H */
