/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef QOS_MBR_HPP_SEEN
#define QOS_MBR_HPP_SEEN

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace oai::upf {

/**
 * @brief QER Maximum Bitrate enforcement with the kernel's own policer.
 *
 * A QER (3GPP TS 29.244 §8.2.8) gives a QoS flow a Maximum Bitrate. Each
 * session's GTP-U TEID gets a `u32` filter on the N3 interface's clsact hook
 * -- uplink on ingress, downlink on egress -- carrying an `action police`
 * token bucket that drops whatever is over the rate:
 *
 *   tc filter add dev N3 egress protocol ip prio P u32 \
 *      match ip protocol 17 0xff match u32 <TEID> 0xffffffff at 32 \
 *      action police rate <MBR> burst <10ms> conform-exceed drop
 *
 * It polices rather than shapes because shaping needs a root qdisc, and the
 * UPF transmits from a single-TX-queue veth where any root qdisc puts every
 * transmit thread behind one lock (HTB and EDT+fq were both measured at about
 * a third of the throughput). §8.2.8 makes the MBR a limit, not a smoothing
 * requirement, so dropping the excess is the right semantics; the burst sets
 * how much of one is absorbed.
 *
 * Nothing is installed until a session actually carries a rate, so a
 * deployment without QoS keeps a bare `noqueue` interface.
 */
class qos_mbr {
 public:
  static qos_mbr& instance() {
    static qos_mbr s;
    return s;
  }

  /** @brief One TEID and the rate that applies to it, in bits per second. */
  struct teid_rate {
    uint32_t teid;
    uint64_t bps;
  };

  /**
   * @brief Set one PDU session's Maximum Bitrates.
   *
   * Call it again whenever the session changes: TEIDs that dropped out are
   * removed, and one whose rate is unchanged keeps its filter -- and so its
   * accumulated credit, which matters because a Session Modification arrives
   * for every handover and must not reset a limiter that did not change.
   *
   * @param ifname the N3 interface
   * @param seid   UP SEID, so a later call can find what this one wrote
   * @param uplink   TEIDs metered on ingress; a rate of 0 is skipped
   * @param downlink TEIDs metered on egress; a rate of 0 is skipped
   */
  bool set_rates(
      const std::string& ifname, uint64_t seid,
      const std::vector<teid_rate>& uplink,
      const std::vector<teid_rate>& downlink);

  /** @brief Drop a released session's filters. Safe if it had none. */
  void clear_rates(uint64_t seid);

 private:
  qos_mbr()               = default;
  qos_mbr(const qos_mbr&) = delete;
  qos_mbr& operator=(const qos_mbr&) = delete;

  /** @brief Add the clsact qdisc, once per interface. */
  bool ensure_clsact(const std::string& ifname);

  struct filter {
    std::string ifname;
    bool egress;
    int prio;  ///< identifies the filter for deletion
    uint32_t teid;
    uint64_t bps;
  };
  bool install(filter& f);
  void remove(const filter& f);

  std::mutex mu_;
  std::unordered_set<std::string> clsact_;  ///< interfaces already set up
  std::unordered_map<uint64_t, std::vector<filter>> by_seid_;
  int next_prio_ = 100;  ///< 1..99 left free for anything hand-installed
};

}  // namespace oai::upf

#endif /* QOS_MBR_HPP_SEEN */
