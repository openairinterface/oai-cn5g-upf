/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_SDF_FILTER_HPP_SEEN
#define FILE_SDF_FILTER_HPP_SEEN

#include <linux/ip.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace oai::upf {

/**
 * @brief A compiled IPFilterRule.
 *
 * The PFCP SDF Filter IE (3GPP TS 29.244 V17.10.0 §8.2.5) carries its Flow
 * Description as the IPFilterRule text of TS 29.212 §5.4.2:
 *
 *     action dir proto from src [ports] to dst [ports]
 *     permit out 6 from any to assigned 5000
 *
 * Parsing that on every packet would cost more than forwarding it, so a PDR
 * compiles the string once when its PDI is set and keeps this instead.
 */
struct sdf_rule {
  bool present = false;  ///< a Flow Description was supplied
  bool valid   = false;  ///< ...and it was understood

  bool out       = true;  ///< direction the rule is written for
  bool any_proto = true;  ///< "ip"
  uint8_t proto  = 0;

  /// Addresses and masks stay in network byte order, because the packet's do
  /// too: matching then costs no conversions.
  bool src_any = true, src_assigned = false;
  uint32_t src_addr = 0, src_mask = 0;
  bool dst_any = true, dst_assigned = false;
  uint32_t dst_addr = 0, dst_mask = 0;

  bool has_src_ports = false;
  uint16_t src_lo = 0, src_hi = 0;  ///< host byte order, inclusive
  bool has_dst_ports = false;
  uint16_t dst_lo = 0, dst_hi = 0;
};

/**
 * @brief Compile a Flow Description.
 *
 * Three outcomes, and the difference between the last two matters:
 *  - empty            -> {present=false}, matches everything, which is what
 *                        the PDI did before SDF filters were looked at.
 *  - understood       -> {present=true, valid=true}.
 *  - not understood   -> {present=true, valid=false}, matches *nothing*, so
 *                        the packet falls through to the next PDR in
 *                        precedence order. Matching everything instead would
 *                        hand all of the session's traffic to whatever rate
 *                        this PDR carries, which is the worse failure.
 */
sdf_rule sdf_compile(const std::string& flow_description);

/**
 * @brief Does @p iph match @p r?
 *
 * @param len    bytes available from @p iph, so ports are never read past
 *               the end of a truncated packet.
 * @param uplink true when the packet travels UE -> network.
 * @param ue_ip  UE address in network byte order, for "assigned".
 */
bool sdf_match(
    const sdf_rule& r, const struct iphdr* iph, std::size_t len, bool uplink,
    uint32_t ue_ip);

}  // namespace oai::upf

#endif /* FILE_SDF_FILTER_HPP_SEEN */
