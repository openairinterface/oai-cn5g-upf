/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
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

#endif /* _PFCP_FAR_H */
