/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_MAR_H
#define _PFCP_MAR_H

#include "ie/steering_functionality.h"
#include "ie/steering_mode.h"
#include "ie/group_ie/access_forwarding_action_info.h"

/**
 * @struct pfcp_mar
 * @brief Multi-Access Rule — BPF map value  (§7.5.2.8)
 *
 * Written by MARProgram::Setup(); read by the mar_apply BPF program
 * for ATSSS packet steering.  The two AFAI entries correspond to the
 * 3GPP access (N3) and non-3GPP access (N9/WLAN) respectively,
 * as named in §7.5.2.8.
 *
 * Steering modes (§8.2.125):
 *   STEER_ACTIVE_STANDBY — traffic to active access, failover to standby
 *   STEER_SMALLEST_DELAY — traffic to access with smaller RTT
 *   STEER_LOAD_BALANCE   — traffic split by weight (§8.2.126)
 *   STEER_PRIORITY_BASED — traffic to highest-priority access (§8.2.127)
 */
struct pfcp_mar {
  __u16 mar_id;  ///< MAR identifier (§8.2.123)
  struct steering_functionality
      steering_functionality;  ///< ATSSS-LL / MPTCP (§8.2.124)
  struct steering_mode
      steering_mode;  ///< Active-Standby/Load-Balance/etc. (§8.2.125)
  struct access_forwarding_action_info
      access_forwarding_action_info_1;  ///< 3GPP access AFAI — weight §8.2.126
                                        ///< / priority §8.2.127
  struct access_forwarding_action_info
      access_forwarding_action_info_2;  ///< Non-3GPP access AFAI — weight
                                        ///< §8.2.126 / priority §8.2.127
} __attribute__((packed));

#endif /* _PFCP_MAR_H */
