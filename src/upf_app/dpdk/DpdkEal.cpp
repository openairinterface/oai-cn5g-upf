/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "DpdkEal.h"

#include <pthread.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <sched.h>

#include <algorithm>
#include <cstring>
#include <set>
#include <sstream>
#include <stdexcept>

#include "logger.hpp"

bool DpdkEal::initialized_ = false;

namespace {

/// Split a whitespace-separated string (used for the extra EAL arguments).
std::vector<std::string> SplitWhitespace(const std::string& text) {
  std::vector<std::string> parts;
  std::istringstream stream(text);
  std::string part;
  while (stream >> part) parts.push_back(part);
  return parts;
}

}  // namespace

//------------------------------------------------------------------------------
std::vector<unsigned> DpdkEal::ParseCoreList(const std::string& core_list) {
  std::set<unsigned> cores;
  std::istringstream stream(core_list);
  std::string token;

  while (std::getline(stream, token, ',')) {
    if (token.empty()) continue;

    const size_t dash = token.find('-');
    try {
      if (dash == std::string::npos) {
        cores.insert(static_cast<unsigned>(std::stoul(token)));
      } else {
        const unsigned first =
            static_cast<unsigned>(std::stoul(token.substr(0, dash)));
        const unsigned last =
            static_cast<unsigned>(std::stoul(token.substr(dash + 1)));
        if (last < first) {
          throw std::runtime_error(
              "DPDK: inverted core range '" + token + "'");
        }
        for (unsigned core = first; core <= last; ++core) cores.insert(core);
      }
    } catch (const std::invalid_argument&) {
      throw std::runtime_error("DPDK: malformed core list '" + core_list + "'");
    } catch (const std::out_of_range&) {
      throw std::runtime_error("DPDK: core id out of range in '" + token + "'");
    }
  }

  return std::vector<unsigned>(cores.begin(), cores.end());
}

//------------------------------------------------------------------------------
void DpdkEal::Init(const oai::config::dpdk_cfg_t& config) {
  if (initialized_) {
    Logger::upf_app().warn("DPDK: EAL already initialised");
    return;
  }

  // --- Build the EAL argument vector ---------------------------------------
  std::vector<std::string> args;
  args.push_back("oai-upf");
  args.push_back("-l");
  args.push_back(config.lcores);
  args.push_back("--main-lcore");
  args.push_back(std::to_string(config.main_lcore));
  args.push_back("-n");
  args.push_back(std::to_string(config.memory_channels));

  if (!config.file_prefix.empty()) {
    args.push_back("--file-prefix");
    args.push_back(config.file_prefix);
  }
  if (!config.socket_mem.empty()) {
    args.push_back("--socket-mem");
    args.push_back(config.socket_mem);
  }

  // Probe only our own NICs. In single-port mode both interfaces name the
  // same device, so it is allowed once.
  args.push_back("-a");
  args.push_back(config.n3.pci_address);
  if (!config.is_single_port()) {
    args.push_back("-a");
    args.push_back(config.n6.pci_address);
  }

  for (const auto& extra : SplitWhitespace(config.extra_eal_args)) {
    args.push_back(extra);
  }

  std::string printable;
  for (const auto& arg : args) printable.append(arg).append(" ");
  Logger::upf_app().info("DPDK: EAL arguments: %s", printable.c_str());

  // rte_eal_init takes a mutable argv and may reorder it.
  std::vector<char*> argv;
  argv.reserve(args.size() + 1);
  for (auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
  argv.push_back(nullptr);

  const int consumed =
      rte_eal_init(static_cast<int>(args.size()), argv.data());
  if (consumed < 0) {
    throw std::runtime_error(
        std::string("DPDK: rte_eal_init failed: ") + rte_strerror(rte_errno));
  }

  initialized_ = true;
  Logger::upf_app().info(
      "DPDK: EAL initialised on %u lcore(s), main lcore %u", rte_lcore_count(),
      rte_get_main_lcore());

  RestoreControlThreadAffinity(config);
}

//------------------------------------------------------------------------------
void DpdkEal::RestoreControlThreadAffinity(
    const oai::config::dpdk_cfg_t& config) {
  // Every lcore EAL owns except the main one polls packets; the control
  // threads this thread will spawn must not be scheduled there.
  std::set<unsigned> packet_lcores;
  for (unsigned lcore : ParseCoreList(config.lcores)) {
    if (lcore != config.main_lcore) packet_lcores.insert(lcore);
  }

  cpu_set_t control_set;
  CPU_ZERO(&control_set);
  const long configured = sysconf(_SC_NPROCESSORS_CONF);
  for (long cpu = 0; cpu < configured && cpu < CPU_SETSIZE; ++cpu) {
    if (packet_lcores.count(static_cast<unsigned>(cpu)) == 0) {
      CPU_SET(cpu, &control_set);
    }
  }

  if (CPU_COUNT(&control_set) == 0) {
    Logger::upf_app().warn(
        "DPDK: every CPU is a packet lcore; leaving the control thread on the "
        "main lcore");
    return;
  }

  const int rc =
      pthread_setaffinity_np(pthread_self(), sizeof(control_set), &control_set);
  if (rc != 0) {
    Logger::upf_app().warn(
        "DPDK: could not set the control thread affinity: %s", strerror(rc));
    return;
  }

  Logger::upf_app().info(
      "DPDK: control threads restricted to %d CPU(s) outside the fast path",
      CPU_COUNT(&control_set));
}

//------------------------------------------------------------------------------
void DpdkEal::Cleanup() {
  if (!initialized_) return;
  rte_eal_cleanup();
  initialized_ = false;
  Logger::upf_app().info("DPDK: EAL cleaned up");
}
