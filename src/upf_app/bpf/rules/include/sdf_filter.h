#ifndef __SDF_FILTER_H__
#define __SDF_FILTER_H__

#include <types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

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
  __u16 lower_bound;  // If not specified in SDF: 0
  __u16 upper_bound;  // If not specified in SDF: 65535
};

struct metadata_filter {
  u32 src_ip;
  u32 dst_ip;
  u8 protocol;
  u16 src_port;
  u16 dst_port;
  // u32 tos;
} __attribute__((aligned(8)));

struct session_qfi {
  u64 seid;
  u8 qfi;
};

struct sdf_filter {
  u8 protocol;  // Required by SDF. 0: icmp, 1: ip, 2: tcp, 3: udp
  struct ip_subnet src_addr;
  struct port_range src_port;
  struct ip_subnet dst_addr;
  struct port_range dst_port;
  struct session_qfi session;
};

#endif  // __SDF_FILTER_H__
