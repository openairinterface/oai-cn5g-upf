/*
 * This file is a modified version from the source.
 * Copyright 2018 The Polycube Authors
 * Copyright 2021 Thiago Navarro
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef __CSUM_H__
#define __CSUM_H__

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <types.h>
#include <errno.h>
#include <linux/version.h>
#include <stdbool.h>

// #include <stddef.h>
// #include <linux/in.h>
// #include <linux/if_ether.h>
// #include <bpf_helpers.h>
// #include <bpf_endian.h>

// static __always_inline __u16
// csum_fold_helper(__u64 csum)
// {
//     int i;
// #pragma unroll
//     for (i = 0; i < 4; i++)
//     {
//         if (csum >> 16)
//             csum = (csum & 0xffff) + (csum >> 16);
//     }
//     return ~csum;
// }

// // static __always_inline __u16
// // iph_csum(struct iphdr *iph)
// // {
// //     iph->check = 0;
// //     unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph,
// sizeof(struct iphdr), 0);
// //     return csum_fold_helper(csum);
// // }

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#define IP_CSUM_OFFSET (sizeof(struct ethhdr) + offsetof(struct iphdr, check))
#define UDP_CSUM_OFFSET                                                        \
  (sizeof(struct ethhdr) + sizeof(struct iphdr) +                              \
   offsetof(struct udphdr, check))
#define TCP_CSUM_OFFSET                                                        \
  (sizeof(struct ethhdr) + sizeof(struct iphdr) +                              \
   offsetof(struct tcphdr, check))
#define ICMP_CSUM_OFFSET                                                       \
  (sizeof(struct ethhdr) + sizeof(struct iphdr) +                              \
   offsetof(struct icmphdr, check))
#define IS_PSEUDO 0x10

#define CSUM_MANGLED_0 ((__sum16) 0xffff)
// #define CSUM_MANGLED_0 ((__force __sum16)0xffff)

static void pcn_update_csum(struct iphdr* iph) {
  u16* next_iph_u16;
  u32 csum = 0;
  int i;

  next_iph_u16 = (u16*) iph;

#pragma clang loop unroll(full)
  for (i = 0; i < sizeof(*iph) >> 1; i++) csum += *next_iph_u16++;

  iph->check = ~((csum & 0xffff) + (csum >> 16));
}

/* checksum related stuff */
static __sum16 pcn_csum_fold(__wsum csum) {
  u32 sum = (u32) csum;
  sum     = (sum & 0xffff) + (sum >> 16);
  sum     = (sum & 0xffff) + (sum >> 16);
  return (__sum16) ~sum;
}

static __sum16 pcn_csum16_add(__sum16 csum, __be16 addend) {
  u16 res = (u16) csum;

  res += (u16) addend;
  return (__sum16) (res + (res < (u16) addend));
}

static __wsum pcn_csum_unfold(__sum16 n) {
  return (__wsum) n;
}

static __wsum pcn_csum_add(__wsum csum, __wsum addend) {
  u32 res = (u32) csum;
  res += (u32) addend;
  return (__wsum) (res + (res < (u32) addend));
}

static void pcn_csum_replace_by_diff(__sum16* sum, __wsum diff) {
  *sum = pcn_csum_fold(pcn_csum_add(diff, ~pcn_csum_unfold(*sum)));
}

static __wsum pcn_csum_diff(
    __be32* from, u32 from_size, __be32* to, u32 to_size, __wsum seed) {
// FIXME: sometimes the LINUX_VERSION_CODE is not aligned with the kernel.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0)
  return bpf_csum_diff(from, from_size, to, to_size, seed);
#else
  if (from_size != 4 || to_size != 4) return -EINVAL;

  __wsum result = pcn_csum_add(*to, ~*from);
  result += seed;
  if (seed > result) result += 1;

  return result;
#endif
}

static int pcn_l3_csum_replace(
    struct xdp_md* ctx, u32 csum_offset, u32 old_value, u32 new_value,
    u32 flags) {
  __sum16* ptr;

  if (unlikely(flags & ~(BPF_F_HDR_FIELD_MASK))) return -EINVAL;

  if (unlikely(csum_offset > 0xffff || csum_offset & 1)) return -EFAULT;

  void* data2     = (void*) (long) ctx->data;
  void* data_end2 = (void*) (long) ctx->data_end;
  if (data2 + csum_offset + sizeof(*ptr) > data_end2) {
    return -EINVAL;
  }

  ptr = (__sum16*) ((void*) (long) ctx->data + csum_offset);
  switch (flags & BPF_F_HDR_FIELD_MASK) {
    case 0:
      pcn_csum_replace_by_diff(ptr, new_value);
      break;
    case 2:
      *ptr = ~pcn_csum16_add(pcn_csum16_add(~(*ptr), ~old_value), new_value);
      break;
    case 4:
      pcn_csum_replace_by_diff(ptr, pcn_csum_add(new_value, ~old_value));
      break;
    default:
      return -EINVAL;
  }
  return 0;
}

static int pcn_l4_csum_replace(
    struct xdp_md* ctx, u32 csum_offset, u32 old_value, u32 new_value,
    u32 flags) {
  // bool is_pseudo = flags & BPF_F_PSEUDO_HDR;
  bool is_mmzero = flags & BPF_F_MARK_MANGLED_0;
  bool do_mforce = flags & BPF_F_MARK_ENFORCE;
  __sum16* ptr;

  if (unlikely(
          flags & ~(BPF_F_MARK_MANGLED_0 | BPF_F_MARK_ENFORCE |
                    BPF_F_PSEUDO_HDR | BPF_F_HDR_FIELD_MASK)))
    return -EINVAL;

  if (unlikely(csum_offset > 0xffff || csum_offset & 1)) return -EFAULT;

  void* data2     = (void*) (long) ctx->data;
  void* data_end2 = (void*) (long) ctx->data_end;

  if (data2 + csum_offset + sizeof(*ptr) > data_end2) {
    return -EINVAL;
  }

  ptr = (__sum16*) ((void*) (long) ctx->data + csum_offset);
  bpf_debug("Here the value of csum_offset %x", (__sum16*) TCP_CSUM_OFFSET);
  bpf_debug("Here the value of ptr %x", *ptr);

  if (is_mmzero && !do_mforce && !*ptr) return 0;

  switch (flags & BPF_F_HDR_FIELD_MASK) {
    case 0:
      pcn_csum_replace_by_diff(ptr, new_value);
      break;
    case 2:
      *ptr = ~pcn_csum16_add(pcn_csum16_add(~(*ptr), ~old_value), new_value);
      break;
    case 4:
      pcn_csum_replace_by_diff(ptr, pcn_csum_add(new_value, ~old_value));
      break;
    default:
      return -EINVAL;
  }

  // It may happen that the checksum of UDP packets is 0;
  // in that case there is an ambiguity because 0 could be
  // considered as a packet without checksum, in that case
  // the checksum has to be "mangled" (i.e., write 0xffff instead of 0).
  if (is_mmzero && !*ptr) *ptr = CSUM_MANGLED_0;
  return 0;
}

// __attribute__((__always_inline__))
// static inline void ipv4_l4_csum(void *data_start, __u32 data_size, __u64
// *csum, struct iphdr *iph) {
//   unsigned short tcpLen = bpf_ntohs(iph->tot_len) - (iph->ihl<<2);
//   __u32 tmp = 0;
//   *csum = bpf_csum_diff(0, 0, &iph->saddr, sizeof(__be32), *csum);
//   *csum = bpf_csum_diff(0, 0, &iph->daddr, sizeof(__be32), *csum);
//   // __builtin_bswap32 equals to htonl()
//   tmp = __builtin_bswap32((__u32)(iph->protocol));
//   *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
//   // tmp = __builtin_bswap32((__u32)(data_size));
//   tmp = __builtin_bswap32((__u32)(tcpLen));
//   *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
//   *csum = bpf_csum_diff(0, 0, data_start, tmp, *csum);
//   *csum = csum_fold_helper(*csum);
// }

// /* set tcp checksum: given IP header and tcp segment */
// void compute_tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload) {
//     register unsigned long sum = 0;
//     unsigned short tcpLen = ntohs(pIph->tot_len) - (pIph->ihl<<2);
//     struct tcphdr *tcphdrp = (struct tcphdr*)(ipPayload);

//     //add the pseudo header
//     //the source ip
//     sum += (pIph->saddr>>16)&0xFFFF;
//     sum += (pIph->saddr)&0xFFFF;
//     //the dest ip
//     sum += (pIph->daddr>>16)&0xFFFF;
//     sum += (pIph->daddr)&0xFFFF;
//     //protocol and reserved: 6
//     sum += htons(IPPROTO_TCP);
//     //the length
//     sum += htons(tcpLen);
//     //add the IP payload
//     //initialize checksum to 0
//     tcphdrp->check = 0;
//     while (tcpLen > 1) {
//         sum += * ipPayload++;
//         tcpLen -= 2;
//     }
//     //if any bytes left, pad the bytes and add
//     if(tcpLen > 0) {
//         //printf("+++++++++++padding, %dn", tcpLen);
//         sum += ((*ipPayload)&htons(0xFF00));
//     }
//       //Fold 32-bit sum to 16 bits: add carrier to result
//       while (sum>>16) {
//           sum = (sum & 0xffff) + (sum >> 16);
//       }
//       sum = ~sum;
//     //set computation result
//     tcphdrp->check = (unsigned short)sum;
// }

/* end checksum related stuff */
#endif  // __CSUM_H__