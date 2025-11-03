#ifndef OPENAIRINTERFACE_FRAMED_ROUTING_BPF_H
#define OPENAIRINTERFACE_FRAMED_ROUTING_BPF_H

#include <types.h>
#include <stdint.h>

struct FramedRoutingKeyBPF {
  uint32_t networkAddress;
  uint32_t subnet;
};

static __always_inline uint32_t
hash_framed_routing_key(struct FramedRoutingKeyBPF* key) {
  uint32_t hash = 17;
  hash          = hash * 31 + key->networkAddress;
  hash          = hash ^ key->subnet;
  return hash;
}

static __always_inline struct FramedRoutingKeyBPF
framed_routing_key_for_ip_cidr(uint32_t ip, uint32_t cidr) {
  const uint32_t ipv4Size = 32;
  // Calculate the subnet address
  uint32_t subnet_mask = 0xffffffff << (ipv4Size - cidr);
  // Calculate the network address
  uint32_t network_address = subnet_mask & ip;

  struct FramedRoutingKeyBPF key = {network_address, subnet_mask};

  return key;
}

#endif  // OPENAIRINTERFACE_FRAMED_ROUTING_BPF_H
