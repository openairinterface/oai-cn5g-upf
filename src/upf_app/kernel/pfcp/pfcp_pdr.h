/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_PDR_H
#define _PFCP_PDR_H

#include "ie/pdr_id.h"
#include "ie/precedence.h"
#include "ie/outer_header_removal.h"
#include "ie/far_id.h"
#include "ie/qer_id.h"
#include "ie/group_ie/pdi.h"
/* Control-plane only — not used by pdr_match XDP program:
 * #include "ie/activate_predefined_rules.h"          §8.2.76
 * #include "ie/deactivate_predefined_rules.h"         §8.2.97
 */

/**
 * @struct pfcp_pdr
 * @brief Packet Detection Rule — BPF map value  (§7.5.2.3)
 *
 * Written by PdrMatchProgram::PopulatePdrRulesMaps(); read by the
 * pdr_match BPF program during per-packet PDR selection.
 * PDRs are stored sorted by ascending precedence so the BPF linear
 * scan stops at the first match (§8.2.11).
 *
 * BPF structural limitations (constraint, not a bug):
 *   Single urr_id slot — spec allows 0..n URR IDs per PDR (§8.2.54)
 *   Single qer_id slot — spec allows 0..n QER IDs per PDR (§8.2.75)
 *   Multi-ID sessions should use pdr_rule_association for extended IDs.
 *
 * Control-plane-only IEs (not used by XDP — CP expands predefined rule names
 * into concrete PDR/FAR/QER entries before writing the BPF map):
 *   activate_predefined_rules   §8.2.76
 *   deactivate_predefined_rules §8.2.97
 */
struct pfcp_pdr {
  struct pdr_id pdr_id;          ///< PDR identifier (§8.2.36)
  struct precedence precedence;  ///< Matching precedence — lower wins (§8.2.11)
  struct pdi pdi;                ///< Packet Detection Information (§7.5.2.3)
  struct outer_header_removal
      outer_header_removal;  ///< GTP-U outer header removal (§8.2.2)
  struct far_id far_id;      ///< Associated FAR (§8.2.74)
  __u32 urr_id;  ///< Associated URR identifier — single slot only (§8.2.54)
  struct qer_id
      qer_id;    ///< Associated QER identifier — single slot only (§8.2.75)
  __u16 mar_id;  ///< Associated MAR for ATSSS steering (§8.2.123); 0 = none
  /* Control-plane only — XDP never reads predefined rule name strings;
   * the CP expands them into concrete map entries before XDP runs.
   * struct activate_predefined_rules activate_predefined_rules;    §8.2.76
   * struct deactivate_predefined_rules deactivate_predefined_rules; §8.2.97
   */
} __attribute__((packed));

#endif /* _PFCP_PDR_H */
