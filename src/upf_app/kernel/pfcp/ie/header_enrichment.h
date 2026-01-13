/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*
 * PFCP Header Enrichment
 * Reference: 3GPP TS 29.244 Section 8.2.67
 */

#ifndef _PFCP_HEADER_ENRICHMENT_H
#define _PFCP_HEADER_ENRICHMENT_H

#include <linux/types.h>
#include "ie_base.h"
#include "pfcp_limits.h"

/**
 * enum pfcp_header_type - Header enrichment types
 * @PFCP_HEADER_TYPE_HTTP: HTTP header enrichment
 */
enum pfcp_header_type {
  PFCP_HEADER_TYPE_HTTP = 0,
};

/**
 * struct header_enrichment - Header Enrichment IE
 * @base: Common IE header
 * @header_type: Type of header (5 bits)
 * @spare: Spare bits (3 bits)
 * @header_field_name_len: Length of header field name
 * @header_field_name: Header field name string
 * @header_field_value_len: Length of header field value
 * @header_field_value: Header field value string
 *
 * Specifies HTTP header field name/value pairs to add to packets.
 *
 * Bit layout:
 *   7   6   5   4   3   2   1   0
 * +---+---+---+---+---+---+---+---+
 * |    spare  |   header_type (5) |
 * +---+---+---+---+---+---+---+---+
 */
struct header_enrichment {
  // struct ie_base base;
  __u8 spare : 3, header_type : 5;
  __u8 header_field_name_len;
  char header_field_name[PFCP_HEADER_FIELD_NAME_MAX_LEN];
  __u8 header_field_value_len;
  char header_field_value[PFCP_HEADER_FIELD_VALUE_MAX_LEN];
} __attribute__((packed));

#endif /* _PFCP_HEADER_ENRICHMENT_H */
