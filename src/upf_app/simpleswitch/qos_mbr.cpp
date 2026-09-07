/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "qos_mbr.hpp"

#include <algorithm>
#include <cstdlib>

#include <fmt/format.h>

#include "logger.hpp"
#include "upf_config.hpp"

extern oai::config::upf_config upf_cfg;

namespace oai::upf {

namespace {
/// Bucket depth: 10 ms of credit, floored so a low rate still passes a full
/// packet. Too small and normal jitter shows up as loss; too large and a
/// session can exceed its MBR for correspondingly longer.
constexpr uint64_t kBurstFloorBytes = 64 * 1024;
uint64_t burst_for(uint64_t rate_bps) {
  const uint64_t ten_ms = rate_bps / 8 / 100;
  return ten_ms > kBurstFloorBytes ? ten_ms : kBurstFloorBytes;
}

/// Runs a tc command; true when it exited 0.
bool run(const std::string& cmd) {
  const int rc = system(cmd.c_str());
  if (rc != 0) {
    Logger::pfcp_switch().error("QoS/MBR: `%s` failed (%d)", cmd.c_str(), rc);
    return false;
  }
  return true;
}
}  // namespace

//------------------------------------------------------------------------------
bool qos_mbr::ensure_clsact(const std::string& ifname) {
  if (clsact_.count(ifname)) return true;

  // clsact is an ingress+egress hook that leaves the root qdisc alone, so the
  // veth keeps `noqueue` and its lock-free transmit path. Already there is
  // fine -- hence the discarded output rather than run().
  const std::string cmd =
      fmt::format("tc qdisc add dev {} clsact 2>/dev/null", ifname);
  system(cmd.c_str());
  clsact_.insert(ifname);
  return true;
}

//------------------------------------------------------------------------------
bool qos_mbr::install(filter& f) {
  if (!ensure_clsact(f.ifname)) return false;

  // The TEID sits at a fixed offset once the outer headers are known: 20 bytes
  // of IPv4 (the UPF's own encapsulation never carries options) + 8 of UDP + 4
  // of GTP-U header, so 32 from the start of the IP header, which is where u32
  // counts from for `protocol ip`.
  const std::string cmd = fmt::format(
      "tc filter add dev {} {} protocol ip prio {} u32 "
      "match ip protocol 17 0xff "
      "match ip dport {} 0xffff "
      "match u32 0x{:08x} 0xffffffff at 32 "
      "action police rate {}bit burst {} mtu 64kb conform-exceed drop",
      f.ifname, f.egress ? "egress" : "ingress", f.prio, 2152, f.teid, f.bps,
      burst_for(f.bps));
  if (!run(cmd)) return false;

  Logger::pfcp_switch().debug(
      "QoS/MBR: TEID 0x%x %s limited to %lu bps (burst %lu B)", f.teid,
      f.egress ? "downlink" : "uplink", f.bps, burst_for(f.bps));
  return true;
}

//------------------------------------------------------------------------------
void qos_mbr::remove(const filter& f) {
  run(fmt::format(
      "tc filter del dev {} {} prio {}", f.ifname,
      f.egress ? "egress" : "ingress", f.prio));
}

//------------------------------------------------------------------------------
bool qos_mbr::set_rates(
    const std::string& ifname, uint64_t seid,
    const std::vector<teid_rate>& uplink,
    const std::vector<teid_rate>& downlink) {
  std::lock_guard<std::mutex> lk(mu_);

  // Only the TEIDs that actually carry a limit are worth a filter.
  std::vector<filter> wanted;
  for (const auto& r : uplink)
    if (r.teid && r.bps) wanted.push_back({ifname, false, 0, r.teid, r.bps});
  for (const auto& r : downlink)
    if (r.teid && r.bps) wanted.push_back({ifname, true, 0, r.teid, r.bps});

  auto& have = by_seid_[seid];

  // Drop what this session no longer wants, or wants at a different rate.
  for (auto it = have.begin(); it != have.end();) {
    const bool keep =
        std::any_of(wanted.begin(), wanted.end(), [&it](const filter& w) {
          return w.teid == it->teid && w.egress == it->egress &&
                 w.bps == it->bps && w.ifname == it->ifname;
        });
    if (keep) {
      ++it;
    } else {
      remove(*it);
      it = have.erase(it);
    }
  }

  bool ok = true;
  for (auto& w : wanted) {
    const bool already =
        std::any_of(have.begin(), have.end(), [&w](const filter& h) {
          return h.teid == w.teid && h.egress == w.egress && h.bps == w.bps;
        });
    if (already) continue;  // untouched, so it keeps its credit
    w.prio = next_prio_++;
    if (install(w))
      have.push_back(w);
    else
      ok = false;
  }

  if (have.empty()) by_seid_.erase(seid);
  return ok;
}

//------------------------------------------------------------------------------
void qos_mbr::clear_rates(uint64_t seid) {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = by_seid_.find(seid);
  if (it == by_seid_.end()) return;
  for (const auto& f : it->second) remove(f);
  by_seid_.erase(it);
}

}  // namespace oai::upf
