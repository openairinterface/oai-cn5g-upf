#ifndef __UPF_XDP_LIMITS_H__
#define __UPF_XDP_LIMITS_H__

/* Compile-time limits for BPF maps and unrolled loops.
 *
 * MAX_PDRS_PER_PDU_SESSION_LIMIT is the upper bound clang's
 *   `#pragma clang loop unroll(full)` will materialise in
 *   xdp_pdr_match_kern.c. With three independent unrolled loops in that
 *   compile unit (UL/DL/ETH match), each iteration carrying ~10-15 BPF
 *   insns of map accesses and conditionals, going much above ~32 pushes
 *   the program past clang's inliner thresholds and triggers verifier
 *   "jump out of range" errors when other map references (tail_call_progs_map
 *   etc.) are added.
 *
 *   The runtime cap is set by `MAX_PDRS_PER_PDU_SESSION` (the .rodata
 *   constant, sourced from YAML `max_pdrs_per_pdu_session`, default 8 /
 *   typical 16). The unroll limit only needs to be >= that value; setting
 *   it equal keeps the verified-instruction count to a minimum.
 *
 *   To raise this materially, replace the unroll pragma in pdr_match with
 *   `bpf_for` (kernel >= 6.3, libbpf >= 1.3) — see the comment at
 *   xdp_pdr_match_kern.c:279.
 */
#define MAX_CPUS 12
#define MAX_TAIL_CALL_PROGS 16
#define MAX_PDRS_PER_PDU_SESSION_LIMIT 16
#define MAX_PDRS_PER_ETH_PDU_SESSION_LIMIT 16

#endif  // __UPF_XDP_LIMITS_H__