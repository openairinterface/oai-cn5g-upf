/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// clang-format off
/* Modified by: Franck Messaoudi <franck.messaoudi@eurecom.fr>
 * Date:        2026-03
 * Changes:     V17.10.0 audit — fixed §-ref in file-level comment:
 *                - Section 7.5.2.3: §7.5.2.3 is Create PDR in V17.10.0;
 *                  the Create FAR grouped IE table is at §7.5.2.4.
 *                  Fixed: §7.5.2.4.
 *              V17.10.0 struct audit — no active fields added:
 *                - redundant_transmission_parameters (§8.2.109): N19
 *                  UP-path redundancy (V16+); added as comment — no current
 *                  XDP implementation for redundant N9 tunnel duplication.
 *              Boy Scout cleanup:
 *                - Replaced bare block comment with changelog + clang-format
 *                  guards and @file Doxygen block.
 *                - "Section X.X.X" notation → §X.X.X throughout.
 *                - Replaced kernel-doc @field list with ///< §-ref inline
 *                  comments on every struct field.
 *                - Noted that bar_id is a scalar __u8 rather than a
 *                  struct bar_id — valid for BPF use, ABI is frozen.
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 (Release 17, 2024-04) — PFCP Protocol
 *              §7.5.2.4   Create FAR grouped IE
 *              §8.2.74    FAR ID         §8.2.17  Apply Action
 *              §8.2.57    BAR ID
 */
// clang-format on

/**
 * @file pfcp_far.h
 * @brief Kernel/user-space shared struct for Forwarding Action Rule (FAR)
 * @author OpenAirInterface, Franck Messaoudi
 * @date 2025 / 2026-03
 *
 * BPF-compatible representation of the PFCP Create FAR IE (§7.5.2.4).
 * Shared between the kernel BPF programs (far_apply.c) and the
 * user-space FAR manager.
 *
 * @warning Changing field order or types is an ABI break — kernel and
 *          user-space must be updated simultaneously.
 *
 * @see 3GPP TS 29.244 §7.5.2.4  — Create FAR grouped IE
 */

#ifndef _PFCP_FAR_H
#define _PFCP_FAR_H

#include "ie/far_id.h"
#include "ie/apply_action.h"
#include "ie/group_ie/forwarding_parameters.h"
#include "ie/group_ie/duplicating_parameters.h"

/**
 * @struct pfcp_far
 * @brief Forwarding Action Rule — BPF map value  (§7.5.2.4)
 *
 * Written by the FAR manager; read by the far_apply BPF program
 * to determine per-packet forwarding, buffering, or dropping actions.
 *
 * @note apply_action.buff=1 requires a valid bar_id to be set.
 *       The BPF program follows the FAR→BAR chain for buffering control.
 *
 * V17.10.0 IE not active — no current XDP implementation:
 *   redundant_transmission_parameters §8.2.109 — N19 UP-path redundancy;
 *   would enable duplication onto a redundant N9 tunnel.
 */
struct pfcp_far {
  struct far_id far_id;  ///< FAR identifier (§8.2.74)
  struct apply_action
      apply_action;  ///< DROP/FORWARD/BUFFER/NOTIFY/DUPLICATE (§8.2.17)
  struct forwarding_parameters
      forwarding_parameters;  ///< Forwarding instructions (§7.5.2.4)
  struct duplicating_parameters
      duplicating_parameters;  ///< Duplication instructions (§7.5.2.4)
  __u8 bar_id;  ///< Buffering Action Rule ID (§8.2.57); 0 = none
  /* V17.10.0 — no current XDP implementation:
   * struct redundant_transmission_parameters redundant_transmission_parameters;
   * §8.2.109
   */
} __attribute__((packed));

typedef struct pfcp_far pfcp_far_t;

#endif /* _PFCP_FAR_H */
