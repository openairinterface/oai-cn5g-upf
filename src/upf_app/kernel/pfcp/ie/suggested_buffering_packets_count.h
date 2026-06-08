/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_SUGGESTED_BUFFERING_PACKETS_COUNT_H
#define _PFCP_SUGGESTED_BUFFERING_PACKETS_COUNT_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct suggested_buffering_packets_count - Suggested Buffering Packets Count
 * IE
 * @packet_count: Suggested max DL packets to buffer (0 = no limit hint)
 *
 * SMF hint for how many downlink packets the UPF should buffer per UE.
 */
struct suggested_buffering_packets_count {
  // struct ie_base base;
  __u8 packet_count;
} __attribute__((packed));

#endif /* _PFCP_SUGGESTED_BUFFERING_PACKETS_COUNT_H */
