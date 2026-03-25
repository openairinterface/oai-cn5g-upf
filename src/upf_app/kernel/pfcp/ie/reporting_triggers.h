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
 * Changes:     Replaced incorrect 8x __u8 field layout with proper
 *              uint16_t bitfield matching 3GPP TS 29.244 §8.2.19 and
 *              the PFCP stack definition in 3gpp_29_244.h
 *              (reporting_triggers_t).
 *              Added REPORTING_TRIGGERS_* bitmask defines for use in
 *              BPF programs and ConvertUrr() when packing into the
 *              __u8 field of struct pfcp_urr in urr_types.h.
 *              Removed ie_base dependency (unused in BPF context).
 * 3GPP Refs:   3GPP TS 29.244 V17.10.0 §8.2.19 -- Reporting Triggers
 */
// clang-format on

/**
 * @file  ie/reporting_triggers.h
 * @brief PFCP Reporting Triggers IE (3GPP TS 29.244 §8.2.19)
 * @author OpenAirInterface, Franck Messaoudi
 * @date 2025 / 2026-03
 *
 * Two representations are provided:
 *
 * 1. struct reporting_triggers  -- 16-bit bitfield, mirrors
 *    reporting_triggers_t from 3gpp_29_244.h.  Used in pfcp_urr.h as
 *    the IE-layer representation passed from the PFCP stack to
 *    ConvertUrr().
 *
 * 2. REPORTING_TRIGGERS_* bitmasks -- single-byte view for packing into
 *    the BPF map field  __u8 reporting_triggers  in struct pfcp_urr
 *    (urr_types.h).  The BPF data plane reads only the lower 8 bits
 *    (byte 0 of the on-wire encoding): perio, volth, timth, start,
 *    stop, droth, volqu, timqu.
 *
 * Bit layout (§8.2.19, Table 7.5.2.6-2, on-wire octet 1 = LSB here):
 *
 *   Bit 15 (MSB) : volqu  -- Volume Quota exhausted
 *   Bit 14       : timqu  -- Time Quota exhausted
 *   Bit 13       : envcl  -- Envelope Closure
 *   Bit 12       : macar  -- MAC Addresses Reporting
 *   Bit 11       : eveth  -- Event Threshold reached
 *   Bit 10       : spare3
 *   Bit  9       : spare2
 *   Bit  8       : spare1
 *   Bit  7       : perio  -- Periodic Reporting
 *   Bit  6       : volth  -- Volume Threshold reached
 *   Bit  5       : timth  -- Time Threshold reached
 *   Bit  4       : quhti  -- Quota Holding Time Indication
 *   Bit  3       : start  -- Start of Traffic
 *   Bit  2       : stop   -- Stop of Traffic  (named 'stop' in spec)
 *   Bit  1       : droth  -- Dropped DL Traffic Threshold reached
 *   Bit  0 (LSB) : liusa  -- Linked Usage Reporting
 *
 * @see 3GPP TS 29.244 V17.10.0 §8.2.19 -- Reporting Triggers
 * @see urr_types.h -- __u8 reporting_triggers in struct pfcp_urr (BPF map)
 * @see pfcp_urr.h  -- struct pfcp_urr uses struct reporting_triggers
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