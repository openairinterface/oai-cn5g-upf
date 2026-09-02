/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef OPENAIRINTERFACE_FRAMED_ROUTING_BPF_H
#define OPENAIRINTERFACE_FRAMED_ROUTING_BPF_H

#include "custom_types.h"
#include <stdint.h>

struct FramedRoutingKeyBPF {
  u32 networkAddress;
  u32 subnet;
};

static __always_inline u32
hash_framed_routing_key(struct FramedRoutingKeyBPF* key) {
  u32 hash = 17;
  hash     = hash * 31 + key->networkAddress;
  hash     = hash ^ key->subnet;
  return hash;
}

static __always_inline struct FramedRoutingKeyBPF
framed_routing_key_for_ip_cidr(u32 ip, u32 cidr) {
  const u32 ipv4Size = 32;
  // Calculate the subnet address
  u32 subnet_mask = 0xffffffff << (ipv4Size - cidr);
  // Calculate the network address
  u32 network_address = subnet_mask & ip;

  struct FramedRoutingKeyBPF key = {network_address, subnet_mask};

  return key;
}

#endif  // OPENAIRINTERFACE_FRAMED_ROUTING_BPF_H
