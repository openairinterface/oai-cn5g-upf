// based on
// https://github.com/netoptimizer/prototype-kernel/blob/master/kernel/samples/bpf/bpf_tail_calls01_kern.c

#ifndef __LOGGER_H__
#define __LOGGER_H__

#include <linux/types.h>
#include <bpf/bpf_helpers.h>

/**
 * @brief Pack a MAC into a u64 for "%012llx": bpf_trace_printk() has no %pM
 *        and takes at most three arguments.
 */
static __always_inline __u64 mac_to_u64(const __u8* mac) {
  return ((__u64) mac[0] << 40) | ((__u64) mac[1] << 32) |
         ((__u64) mac[2] << 24) | ((__u64) mac[3] << 16) |
         ((__u64) mac[4] << 8) | (__u64) mac[5];
}

// #define DEBUG 0
#ifdef BPF_DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)                                                    \
  ({                                                                           \
    char ____fmt[] = fmt;                                                      \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);                 \
  })
#else
#define bpf_debug(fmt, ...)
#endif

#endif  // __LOGGER_H__
