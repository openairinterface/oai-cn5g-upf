/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef RULE_CONVERTER_H_
#define RULE_CONVERTER_H_

#include <memory>

// Flat, packed rule structs shared by every datapath flavour.
#include "pfcp/pfcp_bar.h"
#include "pfcp/pfcp_far.h"
#include "pfcp/pfcp_mar.h"
#include "pfcp/pfcp_pdr.h"
#include "pfcp/pfcp_qer.h"
#include "pfcp/pfcp_urr.h"

namespace pfcp {
class pfcp_pdr;
class pfcp_far;
class pfcp_qer;
class pfcp_urr;
class pfcp_bar;
class pfcp_mar;
}  // namespace pfcp

/**
 * @namespace rules
 * @brief Translation from the C++ PFCP session model to the flat rule structs
 *        a datapath programs into its tables.
 *
 * The structs (kernel/pfcp/*.h) are plain packed C and carry no flavour of
 * their own, so eBPF writes them into BPF maps and DPDK stores them in its
 * lcore tables. These functions are pure: same session objects in, same
 * structs out, no datapath state touched.
 *
 * A null rule yields a zeroed struct rather than an error, so callers can
 * convert optional rules unconditionally.
 *
 * @see 3GPP TS 29.244 §8.2 — Information Elements
 */
namespace rules {

/// Forwarding Action Rule → flat struct (§8.2.26 Apply Action, §8.2.56 OHC).
struct pfcp_far ConvertFar(std::shared_ptr<pfcp::pfcp_far> far);

/// Packet Detection Rule → flat struct (§8.2.2 PDI, §8.2.11 Precedence).
struct pfcp_pdr ConvertPdr(std::shared_ptr<pfcp::pfcp_pdr> pdr);

/// QoS Enforcement Rule → flat struct (§8.2.7 Gate Status, §8.2.9 MBR).
struct pfcp_qer ConvertQer(std::shared_ptr<pfcp::pfcp_qer> qer);

/// Usage Reporting Rule → flat struct (§8.2.40 Measurement Method).
struct pfcp_urr ConvertUrr(std::shared_ptr<pfcp::pfcp_urr> urr);

/// Buffering Action Rule → flat struct (§8.2.47 DL Buffering).
struct pfcp_bar ConvertBar(std::shared_ptr<pfcp::pfcp_bar> bar);

/// Multi-Access Rule → flat struct (§8.2.123 Steering Functionality).
struct pfcp_mar ConvertMar(std::shared_ptr<pfcp::pfcp_mar> mar);

}  // namespace rules

#endif  // RULE_CONVERTER_H_
