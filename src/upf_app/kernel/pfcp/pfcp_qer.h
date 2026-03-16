/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// clang-format off
/* Modified by: Franck Messaoudi <franck.messaoudi@eurecom.fr>
 * Date:        2026-03
 * Changes:     V17.10.0 audit — §7.5.2.5 is correct for Create QER IE;
 *              no §-ref correction needed.
 *              V17.10.0 struct addition — 1 active data-plane IE added:
 *                - averaging_window (§8.2.134): GBR flow smoothing window;
 *                  used by TC shaper for accurate GBR enforcement in 5G NR.
 *              Control-plane / SMF-signalling IEs — added as comments:
 *                - qer_correlation_id (§8.2.19): CP cross-session grouping;
 *                  qer_tc BPF classifier never reads it.
 *                - paging_policy_indicator (§8.2.64): value forwarded to AMF,
 *                  not a per-packet forwarding decision.
 *                - qer_control_indications (§8.2.140): RCSRT/MTES are
 *                  SMF-facing reporting flags; no per-packet role.
 *              Boy Scout cleanup:
 *                - Replaced bare block comment with changelog + clang-format
 *                  guards and @file Doxygen block.
 *                - "Section X.X.X" notation → §X.X.X throughout.
 *                - Replaced kernel-doc @field list with ///< §-ref inline
 *                  comments on every struct field.
 *   ABI BREAK: adding averaging_window changes struct size.  Update
 *     ConvertQer() in qer_tc_user.cpp and kernel qer_tc_kern.c simultaneously.
 *   ie/averaging_window.h must exist in kernel/ie/.
 *   Commented-out IEs (qer_correlation_id, paging_policy_indicator,
 *     qer_control_indications) require no includes until activated.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 *              §7.5.2.5   Create QER grouped IE
 *              §8.2.75    QER ID         §8.2.7   Gate Status
 *              §8.2.8     MBR            §8.2.9   GBR
 *              §8.2.19    QER Correlation ID
 *              §8.2.64    Paging Policy Indicator
 *              §8.2.88    RQI            §8.2.89  QFI
 *              §8.2.134   Averaging Window
 *              §8.2.140   QER Control Indications
 */
// clang-format on

/**
 * @file pfcp_qer.h
 * @brief Kernel/user-space shared struct for QoS Enforcement Rule (QER)
 * @author OpenAirInterface, Franck Messaoudi
 * @date 2025 / 2026-03
 *
 * BPF-compatible representation of the PFCP Create QER IE (§7.5.2.5).
 * Shared between the kernel BPF program (qer_tc_kern.c) and the
 * user-space manager (qer_tc_user.h).
 *
 * @warning Changing field order or types is an ABI break — kernel and
 *          user-space must be updated simultaneously.
 * @warning New fields added in this revision (V17.10.0 update) change
 *          the struct size.  ConvertQer() in qer_tc_user.cpp and the
 *          kernel qer_tc_kern.c must be updated before enabling new fields.
 *
 * @see 3GPP TS 29.244 §7.5.2.5  — Create QER grouped IE
 * @see qer_tc_user.h             — User-space QER map manager
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
