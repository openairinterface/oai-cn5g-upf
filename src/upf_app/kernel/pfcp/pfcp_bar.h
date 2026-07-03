/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_BAR_H
#define _PFCP_BAR_H

#include "ie/dl_data_notification_delay.h"
#include "ie/suggested_buffering_packets_count.h"
/* Control-plane only — not used by bar_apply XDP program:
 * #include "ie/mt_edt_control_information.h"   §8.2.175; MT-EDT trigger is a CP
 * decision
 */

/**
 * @struct pfcp_bar
 * @brief Buffering Action Rule — BPF map value  (§7.5.2.7)
 *
 * Written by BARProgram::Setup(); read by the bar_apply BPF program
 * for DL packet buffering and DDN suppression control.
 *
 * @note dl_data_notification_delay.delay_value > 0 activates DDN
 *       suppression: the data plane skips duplicate notifications within
 *       the delay window (tracked in bar_state_map.last_ddn_ns).
 *
 * Control-plane-only IE (not used by bar_apply XDP program):
 *   mt_edt_control_information — the decision to initiate MT-EDT is taken
 *   by the CP (SMF/AMF); the XDP data path only buffers/forwards packets
 *   and does not drive the EDT state machine (§8.2.175).
 */
struct pfcp_bar {
  __u8 bar_id;  ///< BAR identifier — scalar __u8, not struct bar_id (§8.2.57)
  struct dl_data_notification_delay
      dl_data_notification_delay;  ///< DDN delay in seconds (§8.2.28)
  struct suggested_buffering_packets_count
      suggested_buffering_packets_count;  ///< Max DL packets to buffer
                                          ///< (§8.2.100)
  /* Control-plane only — not read by bar_apply XDP program:
   * struct mt_edt_control_information mt_edt_control_information;  §8.2.175
   */
} __attribute__((packed));

#endif /* _PFCP_BAR_H */
