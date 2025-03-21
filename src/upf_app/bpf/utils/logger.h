// based on
// https://github.com/netoptimizer/prototype-kernel/blob/master/kernel/samples/bpf/bpf_tail_calls01_kern.c

#ifndef __LOGGER_H__
#define __LOGGER_H__

#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <linux/bpf.h>

#define SAMPLE_SIZE 1024ul
#define MAX_CPUS 128
#define MAX_MSG_LEN 128

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#define min(x, y) ((x) < (y) ? (x) : (y))

/* Metadata will be in the perf event before the packet data. */
struct S {
	__u16 cookie;
	__u16 pkt_len;
	char message[MAX_MSG_LEN];
} __packed;
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, int);
	__type(value, 256);
	__uint(max_entries, MAX_CPUS);
	// __uint(pinning, 1);
} logs_map SEC(".maps");

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

// #define bpf_debug3(ctx, fmt, args...)                                       \
//     ({                                                            \
// 		__u64 flags = BPF_F_CURRENT_CPU;						  					\
//         struct S metadata = { .cookie = 0xdead, };                                        \
// 		BPF_SNPRINTF(metadata.message, MAX_MSG_LEN, fmt, ##args); \
// 	    bpf_perf_event_output(ctx, &logs_map, flags, &metadata, sizeof(metadata)); \
//     })

#define bpf_debug3(ctx, fmt, args...) 

#endif  // __LOGGER_H__
