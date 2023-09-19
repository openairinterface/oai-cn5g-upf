#if !defined(PROTOCOLS_GTP_H)
#define PROTOCOLS_GTP_H

#include <types.h>
#include <linux/bpf.h>
#include <stdint.h>

#define GTP_ENCAPSULATED_SIZE                                                  \
  (sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct gtpuhdr) +     \
   sizeof(struct gtpu_extn_pdu_session_container))

#define GTP_UDP_PORT 2152u  //!< TS 29 281
#define GTP_FLAGS 0x30      //!< Version: GTPv1, Protocol Type: GTP, Others: 0
#define GTP_SEQ 0x00
#define GTP_PDU_NUMBER 0x00
#define GTP_NEXT_EXT_TYPE 0x85

#define GTP_EXT_FLAGS 0x34
#define GTP_EXT_MSG_LEN 0x01
#define GTP_EXT_PDU_TYPE 0x00
#define GTP_EXT_QFI 0x05
#define GTP_DEFAULT_QFI 0x08
#define GTP_EXT_NEXT_EXT_TYPE 0x00

// TS 29 281 - Section 6 GTP-U Message Formats
// Table 6.1-1: Messages in GTP-U
#define GTPU_ECHO_REQUEST (1)
#define GTPU_ECHO_RESPONSE (2)
#define GTPU_ERROR_INDICATION (26)
#define GTPU_SUPPORTED_EXTENSION_HEADERS_NOTIFICATION (31)
#define GTPU_END_MARKER (254)
#define GTPU_G_PDU (255)

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
  // Message Type: This field indicates the type of GTP-U message.
  uint8_t message_type;
  // Length: This field indicates the length in octets of the payload, i.e. the
  // rest of the packet following the mandatory part of the GTP header (that is
  // the first 8 octets). The Sequence Number, the N-PDU Number or any Extension
  // headers shall be considered to be part of the payload, i.e. included in the
  // length count.
  uint16_t message_length;
  // Tunnel Endpoint Identifier (TEID): This field unambiguously identifies a
  // tunnel endpoint in the receiving GTP-U protocol entity. The receiving end
  // side of a GTP tunnel locally assigns the TEID value the transmitting side
  // has to use. The TEID value shall be assigned in a non-predictable manner
  // for PGW S5/S8/S2a/S2b interfaces (see 3GPP TS 33.250 [32]). The TEID shall
  // be used by the receiving entity to find the PDP context, except for the
  // following cases:
  // -) The Echo Request/Response and Supported Extension Headers notification
  // messages, where the Tunnel
  //    Endpoint Identifier shall be set to all zeroes
  // -) The Error Indication message where the Tunnel Endpoint Identifier shall
  // be set to all zeros.
  uint32_t teid;

  /*The options start here. */
  uint16_t sequence;
  uint8_t pdu_number;
  uint8_t next_ext_type;

  /*The options start here. */
} __attribute__((packed));

struct gtpu_extn_pdu_session_container {
  uint8_t message_length;
  // PDU Type - This value indicates the structure of the PDU session UP frame.
  // The field takes the value of the PDU Type it identifies; i.e. "0" for PDU
  // Type 0. The PDU type is in bit 4 to bit 7 in the first octet of the frame.
  uint8_t pdu_type;
  // QoS Flow Identifier (QFI): This parameter indicates the QoS Flow Identifier
  // of the QoS flow to which the transferred packet bel
  uint8_t qfi;
  // Next Extension Header Type - This field defines the type of Extension
  // Header that follows this field in the GTP-PDU
  uint8_t next_ext_type;
};

static u32 gtp_handle(
    struct xdp_md* p_ctx, struct gtpuhdr* p_gtpuh, u32 dest_ip);

#endif  // PROTOCOLS_GTP_H
