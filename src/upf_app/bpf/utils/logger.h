// based on
// https://github.com/netoptimizer/prototype-kernel/blob/master/kernel/samples/bpf/bpf_tail_calls01_kern.c

#ifndef __LOGGER_H__
#define __LOGGER_H__

#include <bpf_helpers.h>

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
