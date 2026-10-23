/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef PROTOCOLS_GTP_H
#define PROTOCOLS_GTP_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdint.h>
#include "custom_types.h"
#include "utils/logger.h"

/* ==========================================================================
 * Constants and macros (baseline — unchanged)
 * ========================================================================== */

/** Size of the GTP-U encapsulation this UPF adds (one 4-octet PDU Session
 *  Container). Received G-PDUs vary: see gtpu_inner_offset(). */
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
 * @brief GTP-U PDU Session Container extension header (TS 29.281 §5.2.2.7).
 *
 * Carries the QoS Flow Identifier (QFI) for 5G NR user-plane packets.
 */
struct gtpu_extn_pdu_session_container {
  uint8_t message_length; /**< Extension header length in 4-octet units   */
  uint8_t pdu_type;       /**< PDU Type, high nibble: 0 = DL, 1 = UL      */
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
 * GTP-U extension header chain (TS 29.281 §5.2.1)
 * ========================================================================== */

/** Most extension headers walked per G-PDU; a longer chain is dropped. */
#define GTPU_MAX_EXT_HDRS 4

/** Cap on the GTP-U header with its extension headers, in bytes. A UL PDU
 *  Session Container with every optional field is 48 (TS 38.415 §5.5.2.2). */
#define GTPU_MAX_HDR_LEN 128

/**
 * @brief Length of a G-PDU's GTP-U header including its extension headers,
 *        and the QFI from its PDU Session Container.
 *
 * Walks the chain by each header's length (TS 29.281 §5.2.1). Unknown types
 * marked "comprehension not required" (bit 8 clear, e.g. the Rel-18 PDU Set
 * Information Container) are skipped; other unknown types are rejected. The
 * PDU Session Container may be anywhere in the chain and any length.
 *
 * @param gtpu     G-PDU header, bounds-checked by parse_gtpu_hdr().
 * @param data_end BPF bounds sentinel.
 * @param qfi      Output: QFI (§8.2.89); 0xFF if no container was found.
 * @return Header length in bytes; -1 if malformed, too long, an unknown
 *         comprehension-required type, or without a PDU Session Container.
 */
static __always_inline int gtpu_hdr_len(
    struct gtpuhdr* gtpu, void* data_end, u8* qfi) {
  u32 len = sizeof(*gtpu); /* mandatory + optional fields (present if E) */
  u8 type = gtpu->e ? gtpu->next_ext_type : 0;
  *qfi    = 0xFF;

#pragma clang loop unroll(full)
  for (int i = 0; i < GTPU_MAX_EXT_HDRS; i++) {
    if (!type) break;

    u8* ext = (u8*) gtpu + len;
    if ((void*) (ext + 4) > data_end || !ext[0]) return -1;

    len += ext[0] * 4; /* Extension Header Length, 4-octet units */
    if (len > GTPU_MAX_HDR_LEN) return -1;

    u8* next = (u8*) gtpu + len - 1; /* Next Extension Header Type */
    if ((void*) (next + 1) > data_end) return -1;

    if (type == GTP_NEXT_EXT_TYPE)
      *qfi = ext[2] & 0x3F; /* octet 2, UL and DL (TS 38.415 §5.5.2) */
    else if (type & 0x80)
      return -1; /* unknown, comprehension required */
    type = *next;
  }

  return (type || *qfi == 0xFF) ? -1 : (int) len;
}

/* ==========================================================================
 * parse_gtpu_ext_hdr — walk the extension headers, extract QFI
 * ========================================================================== */

/**
 * @brief Walk a G-PDU's extension headers and return its inner payload.
 *
 * @param gtpu     Pointer to a previously validated GTP-U header.
 * @param data_end BPF bounds sentinel.
 * @param qfi      Output: QFI from the PDU Session Container (§8.2.89).
 * @return Pointer to the inner payload (Ethernet frame or IP packet), not
 *         bounds-checked; NULL to drop (see gtpu_hdr_len()).
 */
static __always_inline void* parse_gtpu_ext_hdr(
    struct gtpuhdr* gtpu, void* data_end, u8* qfi) {
  int len = gtpu_hdr_len(gtpu, data_end, qfi);
  if (len < 0) {
    bpf_debug("GTP-U: unsupported or malformed extension headers");
    return NULL;
  }
  return (void*) gtpu + len;
}

/**
 * @brief Offset of an N3 G-PDU's inner payload from the start of its frame.
 *
 * For stages after the N3 entry programs: they re-walk the headers instead
 * of carrying the offset along.
 *
 * @param data     Start of the frame (outer Ethernet header).
 * @param data_end BPF bounds sentinel.
 * @return Offset in bytes; -1 unless a G-PDU with a 20-byte outer IPv4 header
 *         that parse_gtpu_ext_hdr() accepts.
 */
static __always_inline int gtpu_inner_offset(void* data, void* data_end) {
  struct iphdr* iph    = data + sizeof(struct ethhdr);
  struct gtpuhdr* gtpu = (void*) (iph + 1) + sizeof(struct udphdr);
  u8 qfi;

  if ((void*) (gtpu + 1) > data_end || iph->ihl != 5 ||
      gtpu->message_type != GTPU_G_PDU)
    return -1;

  int len = gtpu_hdr_len(gtpu, data_end, &qfi);
  if (len < 0) return -1;
  return (int) (sizeof(struct ethhdr) + sizeof(struct iphdr) +
                sizeof(struct udphdr)) +
         len;
}

#endif /* PROTOCOLS_GTP_H */
