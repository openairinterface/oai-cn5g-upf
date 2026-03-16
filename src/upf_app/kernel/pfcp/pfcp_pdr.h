/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

// clang-format off
/* Modified by: Franck Messaoudi <franck.messaoudi@eurecom.fr>
 * Date:        2026-03
 * Changes:     V17.10.0 audit — fixed §-ref in file-level comment:
 *                - Section 7.5.2.2: §7.5.2.2 is the PFCP Session
 *                  Establishment Request message overview in V17.10.0;
 *                  the Create PDR grouped IE table is at §7.5.2.3.
 *                  Fixed: §7.5.2.3.
 *              V17.10.0 struct additions — 1 active IE added:
 *                - mar_id (__u16, §8.2.123): required for ATSSS — the
 *                  fast path must know which MAR rule applies to the
 *                  matched PDR.  Without this field the PDR→MAR chain
 *                  cannot be followed in the XDP pipeline.
 *              Control-plane-only IEs — added as comments, not active fields:
 *                - activate_predefined_rules (§8.2.76): CP expands rule
 *                  names into concrete map entries before XDP runs; XDP
 *                  never interprets predefined rule name strings.
 *                - deactivate_predefined_rules (§8.2.97): same reason;
 *                  mid-session CP operation only.
 *              Boy Scout cleanup:
 *                - Replaced bare block comment with changelog + clang-format
 *                  guards and @file Doxygen block.
 *                - "Section X.X.X" notation → §X.X.X throughout.
 *                - Replaced kernel-doc @field list with ///< §-ref inline
 *                  comments on every struct field.
 *   ABI BREAK: adding mar_id changes struct size.  Update ConvertPdr() /
 *     SessionProgramManager and the kernel pdr_match.c simultaneously.
 *   ie/deactivate_predefined_rules.h is referenced in comments only;
 *     no include required until the field is activated.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 *              §7.5.2.3   Create PDR grouped IE
 *              §8.2.36    PDR ID         §8.2.11  Precedence
 *              §8.2.2     Outer Header Removal
 *              §8.2.74    FAR ID         §8.2.54  URR ID
 *              §8.2.75    QER ID         §8.2.76  Activate Predefined Rules
 *              §8.2.97    Deactivate Predefined Rules
 *              §8.2.123   MAR ID
 */
// clang-format on

/**
 * @file pfcp_pdr.h
 * @brief Kernel/user-space shared struct for Packet Detection Rule (PDR)
 * @author OpenAirInterface, Franck Messaoudi
 * @date 2025 / 2026-03
 *
 * BPF-compatible representation of the PFCP Create PDR IE (§7.5.2.3).
 * Shared between the kernel BPF program (pdr_match.c) and the
 * user-space manager (pdr_match_user.h).
 *
 * @warning Changing field order or types is an ABI break — kernel and
 *          user-space must be updated simultaneously.
 *
 * @see 3GPP TS 29.244 §7.5.2.3  — Create PDR grouped IE
 * @see pdr_match_user.h          — User-space PDR map manager
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
