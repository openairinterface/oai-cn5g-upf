/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PFCP_REPORTING_TRIGGERS_H
#define _PFCP_REPORTING_TRIGGERS_H

#include <linux/types.h>

/* ==========================================================================
 * IE bitfield struct  (mirrors reporting_triggers_t in 3gpp_29_244.h)
 * ========================================================================== */

/**
 * @struct reporting_triggers
 * @brief 16-bit bitfield representation of the Reporting Triggers IE.
 *
 * Field order matches the on-wire layout of 3GPP TS 29.244 §8.2.19.
 * Packed to 2 bytes.
 *
 * Used by the PFCP stack (pfcp::pfcp_urr) and ConvertUrr() to fill
 * struct pfcp_urr before writing to the BPF map.
 */
struct reporting_triggers {
  __u16 liusa : 1;   ///< Linked Usage Reporting (bit 0)
  __u16 droth : 1;   ///< Dropped DL Traffic Threshold (bit 1)
  __u16 stop : 1;    ///< Stop of Traffic (bit 2)
  __u16 start : 1;   ///< Start of Traffic (bit 3)
  __u16 quhti : 1;   ///< Quota Holding Time Indication (bit 4)
  __u16 timth : 1;   ///< Time Threshold reached (bit 5)
  __u16 volth : 1;   ///< Volume Threshold reached (bit 6)
  __u16 perio : 1;   ///< Periodic Reporting (bit 7)
  __u16 spare1 : 1;  ///< Reserved (bit 8)
  __u16 spare2 : 1;  ///< Reserved (bit 9)
  __u16 spare3 : 1;  ///< Reserved (bit 10)
  __u16 eveth : 1;   ///< Event Threshold reached (bit 11)
  __u16 macar : 1;   ///< MAC Addresses Reporting (bit 12)
  __u16 envcl : 1;   ///< Envelope Closure (bit 13)
  __u16 timqu : 1;   ///< Time Quota exhausted (bit 14)
  __u16 volqu : 1;   ///< Volume Quota exhausted (bit 15)
} __attribute__((packed));

/* ==========================================================================
 * Bitmask defines for BPF map packing  (__u8 in struct pfcp_urr)
 *
 * ConvertUrr() uses these to build the single __u8 byte stored in
 * urr_types.h::pfcp_urr::reporting_triggers from the IE bitfields above.
 *
 * Only the lower 8 bits (byte 0 on-wire) are actionable by the XDP data
 * plane -- the upper 8 bits (eveth, macar, envcl, timqu, volqu, spare*)
 * require control-plane handling and are not evaluated per-packet.
 * ========================================================================== */

#define REPORTING_TRIGGERS_LIUSA (1u << 0) /**< Linked Usage Reporting     */
#define REPORTING_TRIGGERS_DROTH (1u << 1) /**< Dropped DL Traffic Thresh  */
#define REPORTING_TRIGGERS_STOP (1u << 2)  /**< Stop of Traffic            */
#define REPORTING_TRIGGERS_START (1u << 3) /**< Start of Traffic           */
#define REPORTING_TRIGGERS_QUHTI (1u << 4) /**< Quota Holding Time         */
#define REPORTING_TRIGGERS_TIMTH (1u << 5) /**< Time Threshold             */
#define REPORTING_TRIGGERS_VOLTH (1u << 6) /**< Volume Threshold           */
#define REPORTING_TRIGGERS_PERIO (1u << 7) /**< Periodic Reporting         */

#endif /* _PFCP_REPORTING_TRIGGERS_H */