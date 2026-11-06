/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_BAR_H
#define _PFCP_BAR_H

#include "ie/dl_data_notification_delay.h"
#include "ie/suggested_buffering_packets_count.h"

/**
 * @struct pfcp_bar
 * @brief Copy of a Buffering Action Rule IE (Create BAR, TS 29.244
 *        Table 7.5.2.6-1), carried in rules_match_pdr (pipeline_types.h).
 *        The XDP BAR program does not read it: it reads struct bar_config
 *        (bar_types.h) from bar_config_map (bar_maps.h).
 */
struct pfcp_bar {
  __u8 bar_id;  ///< BAR identifier — scalar __u8, not struct bar_id (§8.2.57)
  struct dl_data_notification_delay
      dl_data_notification_delay;  ///< DDN delay in units of 50 ms (§8.2.28)
  struct suggested_buffering_packets_count
      suggested_buffering_packets_count;  ///< Max DL packets to buffer
                                          ///< (§8.2.100)
  /* Control-plane only — not read by bar_apply XDP program:
   * struct mt_edt_control_information mt_edt_control_information;  §8.2.172
   */
} __attribute__((packed));

#endif /* _PFCP_BAR_H */
