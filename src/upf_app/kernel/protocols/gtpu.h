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
 * Changes:     Boy Scout cleanup — added two inline helpers:
 *                parse_gtpu_hdr()    validates GTP-U header, extracts F-TEID
 *                parse_gtpu_ext_hdr() validates PDU Session Container,
 *                                        extracts QFI
 *              Removed stale gtp_handle() forward declaration (unused).
 *              Structs, constants, and macros unchanged.
 * 3GPP Refs:   3GPP TS 29.281 V17.x.x §5.1    — GTP-U header format
 *              3GPP TS 29.281 V17.x.x §5.5.3.3 — PDU Session Container
 *              3GPP TS 29.244 V17.10.0 §8.2.3  — F-TEID IE
 *              3GPP TS 29.244 V17.10.0 §8.2.89 — QFI IE
 */
// clang-format on

/**
 * @file  protocols/gtpu.h
 * @brief GTP-U header definitions and parsing helpers for XDP programs.
 *
 * Structs, constants, and macros are the original baseline.
 * Two inline helpers have been added to centralise the GTP-U parsing
 * logic duplicated across xdp_n3_entry.c and xdp_n3_eth_entry.c.
 *
 * Used by:
 *    xdp_n3_entry.c,
 *    xdp_n3_eth_entry.c,
 *    xdp_n6_eth_entry.c,
 *    protocols/udp.h
 */

#ifndef PROTOCOLS_GTP_H
#define PROTOCOLS_GTP_H

#include <linux/bpf.h>
#include <linux/udp.h>
#include <stdint.h>
#include "linux/custom_types.h"
#include "utils/logger.h"

/* ==========================================================================
 * Constants and macros (baseline — unchanged)
 * ========================================================================== */

/** Total size of the GTP-U encapsulation headers added before the payload. */
#define GTP_ENCAPSULATED_SIZE                                                  \
  (sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct gtpuhdr) +     \
   sizeof(struct gtpu_extn_pdu_session_container))

#define GTP_UDP_PORT 2152u /**< IANA-assigned GTP-U port (TS 29.281)  */
#define GTP_FLAGS 0x30     /**< GTPv1, PT=GTP, others=0               */
#define GTP_SEQ 0x00
#define GTP_PDU_NUMBER 0x00
#define GTP_NEXT_EXT_TYPE 0x85

#define GTP_EXT_FLAGS 0x34
#define GTP_EXT_MSG_LEN 0x01
#define GTP_EXT_PDU_TYPE 0x00
#define GTP_EXT_QFI 0x05
#define GTP_DEFAULT_QFI 0x08
#define GTP_EXT_NEXT_EXT_TYPE 0x00

/* GTP-U message types (TS 29.281 Table 6.1-1) */
#define GTPU_ECHO_REQUEST (1)
#define GTPU_ECHO_RESPONSE (2)
#define GTPU_ERROR_INDICATION (26)
#define GTPU_SUPPORTED_EXTENSION_HEADERS_NOTIFICATION (31)
#define GTPU_END_MARKER (254)
#define GTPU_G_PDU (255)

/* ==========================================================================
 * GTP-U header struct (baseline — unchanged)
 * ========================================================================== */

/**
 * @brief GTP-U v1 header (TS 29.281 §5.1).
 *
 * Fixed 8-byte mandatory part followed by optional fields
 * (Sequence Number, N-PDU Number, Next Extension Header Type).
 */
struct gtpuhdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
  unsigned int pn : 1;
  unsigned int s : 1;
  unsigned int e : 1;
  unsigned int spare : 1;
  unsigned int pt : 1;
  unsigned int version : 3;
#elif __BYTE_ORDER == __BIG_ENDIAN
  unsigned int version : 3;
  unsigned int pt : 1;
  unsigned int spare : 1;
  unsigned int e : 1;
  unsigned int s : 1;
  unsigned int pn : 1;
#else
#error "Please fix <bits/endian.h>"
#endif
  uint8_t message_type;    /**< Message Type (G-PDU = 0xFF)               */
  uint16_t message_length; /**< Payload length excl. mandatory 8 bytes     */
  uint32_t teid;           /**< Tunnel Endpoint Identifier (§8.2.3)        */
  uint16_t sequence;
  uint8_t pdu_number;
  uint8_t next_ext_type;
} __attribute__((packed));

/* ==========================================================================
 * PDU Session Container extension header (baseline — unchanged)
 * ========================================================================== */

/**
 * @brief GTP-U PDU Session Container extension header (TS 29.281 §5.5.3.3).
 *
 * Carries the QoS Flow Identifier (QFI) for 5G NR user-plane packets.
 */
struct gtpu_extn_pdu_session_container {
  uint8_t message_length; /**< Extension header length in 4-octet units   */
  uint8_t pdu_type;       /**< PDU Type (0 = UL, 1 = DL)                  */
  uint8_t qfi;            /**< QoS Flow Identifier (§8.2.89)              */
  uint8_t next_ext_type;  /**< Next Extension Header Type (0x00 = none)   */
};

/* ==========================================================================
 * parse_gtpu_hdr — validate GTP-U header and extract F-TEID
 * ========================================================================== */

/**
 * @brief Validate the GTP-U header and extract the F-TEID.
 *
 * Only G-PDU messages (type 0xFF) carry user-plane payload.  Other
 * message types (Echo, Error Indication, End Marker …) are signalled
 * via @p pass so the caller can hand them to the kernel stack.
 *
 * @param udp      Pointer to a previously validated outer UDP header.
 * @param data_end BPF bounds sentinel.
 * @param gtpu_out Output: pointer to the GTP-U header.
 * @param teid     Output: F-TEID in host byte order (§8.2.3).
 * @param pass     Output: true if the message type should be XDP_PASS'd.
 * @return true if the header is valid and contains a G-PDU;
 *         false on bounds error (XDP_DROP) or non-G-PDU (@p pass = true).
 */
static __always_inline bool parse_gtpu_hdr(
    struct udphdr* udp, void* data_end, struct gtpuhdr** gtpu_out, u32* teid,
    bool* pass) {
  *pass     = false;
  *gtpu_out = (void*) (udp + 1);

  if ((void*) (*gtpu_out + 1) > data_end) {
    bpf_debug("GTP-U: malformed GTP-U header");
    return false;
  }

  if ((*gtpu_out)->message_type != GTPU_G_PDU) {
    bpf_debug(
        "GTP-U: message type 0x%02x is not G-PDU — passing to kernel",
        (*gtpu_out)->message_type);
    *pass = true;
    return false;
  }

  *teid = bpf_ntohl((*gtpu_out)->teid);
  return true;
}

/* ==========================================================================
 * parse_gtpu_ext_hdr — validate PDU Session Container, extract QFI
 * ========================================================================== */

/**
 * @brief Validate the PDU Session Container extension header and extract QFI.
 *
 * The PDU Session Container immediately follows the GTP-U header for
 * 5G NR packets (TS 29.281 §5.5.3.3).  Returns a pointer to the first
 * byte of the inner payload (Ethernet or IPv4 frame).
 *
 * @param gtpu     Pointer to a previously validated GTP-U header.
 * @param data_end BPF bounds sentinel.
 * @param gtpu_ext_out  Output: pointer to the PDU Session Container.
 * @param qfi      Output: QFI value from the extension header (§8.2.89).
 * @return Pointer to the inner payload on success; NULL on bounds error.
 */
static __always_inline void* parse_gtpu_ext_hdr(
    struct gtpuhdr* gtpu, void* data_end,
    struct gtpu_extn_pdu_session_container** gtpu_ext_out, u8* qfi) {
  *gtpu_ext_out = (void*) (gtpu + 1);

  if ((void*) (*gtpu_ext_out + 1) > data_end) {
    bpf_debug("GTP-U: malformed PDU Session Container");
    return NULL;
  }

  *qfi = (*gtpu_ext_out)->qfi;
  return (void*) (*gtpu_ext_out + 1);
}

#endif /* PROTOCOLS_GTP_H */
