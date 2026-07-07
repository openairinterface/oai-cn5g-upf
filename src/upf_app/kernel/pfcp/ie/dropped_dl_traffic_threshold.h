/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_IE_DROPPED_DL_TRAFFIC_THRESHOLD_H
#define _PFCP_IE_DROPPED_DL_TRAFFIC_THRESHOLD_H

#include <linux/types.h>
#include "ie_base.h"

/**
 * struct dropped_dl_traffic_threshold - Dropped DL Traffic Threshold IE
 * @flags:                         Bitfield — dlpa (bit 0): threshold is in
 *                                 downlink packets; dlby (bit 1): threshold
 *                                 is in bytes. Bits 2–7 are spare.
 * @downlink_packets:              Packet-count threshold for dropped DL
 *                                 traffic (valid when dlpa=1, big-endian).
 * @number_of_bytes_of_downlink_data: Byte-count threshold for dropped DL
 *                                 traffic (valid when dlby=1, big-endian).
 *
 * When the number of dropped downlink packets/bytes for a URR-monitored
 * flow reaches the configured threshold the UPF shall send a Dropped DL
 * Traffic Threshold report to the SMF (3GPP TS 29.244 §8.2.49).
 */
struct dropped_dl_traffic_threshold {
  __u8 flags;                             /* bits: [1]=dlby [0]=dlpa        */
  __u64 downlink_packets;                 /* packet threshold, big-endian   */
  __u64 number_of_bytes_of_downlink_data; /* byte threshold,   big-endian   */
} __attribute__((packed));

/* Flag bit positions */
#define DDTH_FLAG_DLPA (1 << 0) /* threshold in downlink packets */
#define DDTH_FLAG_DLBY (1 << 1) /* threshold in bytes            */

#endif /* _PFCP_IE_DROPPED_DL_TRAFFIC_THRESHOLD_H */