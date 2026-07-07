/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_QER_H
#define _PFCP_QER_H

#include "ie/qer_id.h"
#include "ie/gate_status.h"
#include "ie/gbr.h"
#include "ie/mbr.h"
#include "ie/qfi.h"
#include "ie/reflective_qos.h"
#include "ie/averaging_window.h" /* §8.2.134 — V17.10.0 addition */
/* Control-plane / SMF-signalling only — not used by qer_tc BPF classifier:
 * #include "ie/qer_correlation_id.h"         §8.2.19; CP cross-session
 * correlation only #include "ie/paging_policy_indicator.h"    §8.2.64;
 * forwarded to AMF, not per-packet #include "ie/qer_control_indications.h"
 * §8.2.140; RCSRT/MTES are SMF-facing flags
 */

/**
 * @struct pfcp_qer
 * @brief QoS Enforcement Rule — BPF map value  (§7.5.2.5)
 *
 * Written by QERProgram::Setup(); read by the qer_tc BPF classifier
 * for per-flow rate limiting and gate enforcement.
 *
 * V17.10.0 addition (active data-plane field):
 *   averaging_window — requires ConvertQer() update.
 *
 * Control-plane / SMF-signalling IEs (not used by qer_tc BPF classifier):
 *   qer_correlation_id     — CP cross-session correlation; XDP never reads it
 * (§8.2.19). paging_policy_indicator — forwarded to AMF, not a per-packet
 * forwarding decision (§8.2.64). qer_control_indications — RCSRT/MTES are
 * SMF-facing reporting flags; no per-packet role (§8.2.140).
 */
struct pfcp_qer {
  struct qer_id qer_id;            ///< QER identifier (§8.2.75)
  struct gate_status gate_status;  ///< UL/DL gate open/closed (§8.2.7)
  struct mbr maximum_bitrate;      ///< Maximum Bit Rate (§8.2.8)
  struct gbr guaranteed_bitrate;   ///< Guaranteed Bit Rate (§8.2.9)
  struct qfi qos_flow_identifier;  ///< QoS Flow Identifier (§8.2.89)
  struct rqi reflective_qos;       ///< Reflective QoS Indication (§8.2.88)
  struct averaging_window
      averaging_window;  ///< GBR smoothing window (§8.2.134)
  /* Control-plane / SMF-signalling only — not read by qer_tc BPF classifier:
   * struct qer_correlation_id qer_correlation_id;              CP cross-session
   * correlation (§8.2.19) struct paging_policy_indicator
   * paging_policy_indicator;    AMF paging value, not per-packet (§8.2.64)
   * struct qer_control_indications qer_control_indications;    RCSRT/MTES SMF
   * flags (§8.2.140)
   */
} __attribute__((packed));

#endif /* _PFCP_QER_H */
