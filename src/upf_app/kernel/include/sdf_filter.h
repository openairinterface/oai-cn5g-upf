#ifndef __SDF_FILTER_H__
#define __SDF_FILTER_H__

#include "linux/custom_types.h"

/*---------------------------------------------------------------------------------------------------------------*/
// /**
//  * @brief Generate unique minor ID for TC classid
//  *
//  * Creates a 16-bit minor ID from session ID (seid) and QFI using a
//  * simple hash function. This ID is used as the minor number in the
//  * TC classid (handle) to uniquely identify each QoS flow.
//  *
//  * Hash Algorithm:
//  * - Extracts lower 48 bits of seid (upper bits rarely change)
//  * - Combines with QFI using XOR and rotation
//  * - Ensures value fits in 16 bits (0-65535)
//  *
//  * @param seid Session ID (64-bit PFCP session identifier)
//  * @param qfi QoS Flow Identifier (8-bit, typically 1-63)
//  * @return 16-bit minor ID for TC classid
//  *
//  * Example:
//  * ```c
//  * u64 seid = 0x123456789ABCDEF0;
//  * u8 qfi = 5;
//  * u16 minor = generate_minor_id(seid, qfi);
//  * u32 classid = TC_H_MAKE(HTB_ROOT_MAJOR, minor);
//  * skb->tc_classid = classid;  // e.g., 0x00010A3F
//  * ```
//  *
//  * Note: Hash collisions are possible but rare in practice. If collision
//  * handling is needed, consider using a map to track assignments.
//  */
// static __always_inline u16 generate_minor_id(u64 seid, u8 qfi) {
//   /* Extract lower 48 bits of seid (typical SEID format) */
//   u64 seid_lower = seid & 0x0000FFFFFFFFFFFF;

//   /* Combine with QFI using XOR and bit rotation for better distribution */
//   u32 hash = (u32) ((seid_lower >> 16) ^ (seid_lower & 0xFFFF));
//   hash ^= (qfi << 8) | qfi;

//   /* Additional mixing to reduce collisions */
//   hash ^= (hash >> 16);
//   hash *= 0x85EBCA6B;  /* Multiplicative hash constant */
//   hash ^= (hash >> 13);

//   /* Ensure result fits in 16 bits and avoid reserved values */
//   u16 minor = (u16) (hash & 0xFFFF);

//   /* Avoid minor ID 0 (reserved) */
//   if (minor == 0) {
//     minor = 1;
//   }

//   return minor;
// }

static inline u16 generate_minor_id(u64 seid, u8 qfi) {
  u16 hash     = (seid ^ (seid >> 16) ^ (seid >> 32) ^ (seid >> 48));
  u16 minor_id = (hash + (qfi * 37)) & 0xFFFF;  // Avoid modulo, use bitmask

  // Limit minor_id to a max of 9999
  minor_id = (minor_id > 9999) ? 9999 : minor_id;

  return minor_id ? minor_id : 1;  // Ensure nonzero
}
/*---------------------------------------------------------------------------------------------------------------*/

struct ip_subnet {
  u8 type;
  /*
   * 0: any, 1: ip4, 2: ip6
   * If type != any, ip field has meaningful value.
   * If IPv4 -> lower 32 bits. If IPv6 -> all 128 bits.
   */
  u128 ip;
  /*
   * If type != any, mask field has meaningful value.
   * If IPv4 mask -> lower 32 bits. If IPv6 mask -> all 128 bits.
   * Should always be applied to matching ip (except type == any).
   */
  u128 mask;
};

struct port_range {
  u16 lower_bound;  // If not specified in SDF: 0
  u16 upper_bound;  // If not specified in SDF: 65535
};

struct packet_filter {
  u32 src_ip;
  u32 dst_ip;
  u16 protocol;
  u16 src_port;
  u16 dst_port;
  // u32 tos;
} __attribute__((aligned(8)));

struct session_qfi {
  u64 seid;
  u8 qfi;
};

struct sdf_filtr {
  u16 protocol;
  struct ip_subnet src_addr;
  struct port_range src_port;
  struct ip_subnet dst_addr;
  struct port_range dst_port;
  struct session_qfi session;
};

#endif  // __SDF_FILTER_H__
