/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "NextHopFinder.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

#include "CmdRunner.hpp"
#include "logger.hpp"

/* ------------------------------------------------------------------------- */
/**
 * @brief Trim whitespace from a string in place.
 */
static inline void rtrim_in_place(std::string& s) {
  s.erase(
      std::remove_if(
          s.begin(), s.end(), [](unsigned char c) { return std::isspace(c); }),
      s.end());
}

/* ------------------------------------------------------------------------- */
/**
 * @brief Look up the netmask configured on the local interface that owns the
 *        given IPv4 address.
 *
 * Iterates over all local interfaces via getifaddrs(3) and returns the
 * netmask of the interface whose address matches @p local_ip_be. Both the
 * input and the returned netmask are in network byte order.
 *
 * If no matching interface is found, returns 0 — callers must treat this as
 * "unknown" and fall back to a strict equality check.
 *
 * @param local_ip_be  Local IPv4 address in network byte order.
 * @return netmask in network byte order (e.g. 0x00FFFFFF for /24), or 0 if
 *         the address is not configured on any local interface.
 */
static uint32_t lookup_local_netmask(uint32_t local_ip_be) {
  struct ifaddrs* ifa_list = nullptr;
  if (getifaddrs(&ifa_list) != 0 || ifa_list == nullptr) {
    Logger::upf_app().warn(
        "lookup_local_netmask: getifaddrs failed (%s)", strerror(errno));
    return 0;
  }

  uint32_t mask_be = 0;
  for (struct ifaddrs* ifa = ifa_list; ifa != nullptr; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == nullptr || ifa->ifa_netmask == nullptr) {
      continue;
    }
    if (ifa->ifa_addr->sa_family != AF_INET) {
      continue;
    }
    const auto* sin =
        reinterpret_cast<const struct sockaddr_in*>(ifa->ifa_addr);
    if (sin->sin_addr.s_addr != local_ip_be) {
      continue;
    }
    const auto* sin_mask =
        reinterpret_cast<const struct sockaddr_in*>(ifa->ifa_netmask);
    mask_be = sin_mask->sin_addr.s_addr;
    break;
  }

  freeifaddrs(ifa_list);
  return mask_be;
}

/* ------------------------------------------------------------------------- */
/**
 * @brief Test whether two IPv4 addresses share the same subnet, using the
 *        netmask configured on the local interface that owns @p local_ip_be.
 *
 * Both addresses must be in network byte order. The function discovers the
 * appropriate netmask at runtime by inspecting local interface configuration
 * (via getifaddrs), so it works correctly for arbitrary CIDR prefixes
 * (/24, /26, /28, ...) without any hardcoded assumption.
 *
 * If the local netmask cannot be determined (e.g. @p local_ip_be is not
 * configured on any local interface), the function falls back to strict
 * equality.
 *
 * @param local_ip_be   Local (host) IP in network byte order. Its interface
 *                      configuration determines the netmask.
 * @param remote_ip_be  Remote (peer) IP in network byte order.
 * @return non-zero if both addresses share the same subnet, zero otherwise.
 */
int NextHopFinder::sameSubnet(uint32_t local_ip_be, uint32_t remote_ip_be) {
  const uint32_t mask_be = lookup_local_netmask(local_ip_be);
  if (mask_be == 0) {
    Logger::upf_app().warn(
        "sameSubnet: no local interface owns the given IP, falling back to "
        "strict equality");
    return local_ip_be == remote_ip_be;
  }

  const int result = (local_ip_be & mask_be) == (remote_ip_be & mask_be);

  return result;
}

/* ------------------------------------------------------------------------- */
/**
 * @brief Resolve the next-hop IP for a given destination using the kernel
 *        routing table.
 *
 * Wraps ``ip -o route get <ip>`` and parses two response formats:
 *
 *   * On-link  : ``<dst> dev <iface> src <src> ...``
 *   * Via gw   : ``<dst> via <gw> dev <iface> src <src> ...``
 *
 * For on-link destinations, returns @p ipDest_be itself. For destinations
 * reached via a gateway, returns the gateway's IP.
 *
 * @param ipDest_be  Destination IP in network byte order.
 * @return next-hop IP in network byte order.
 * @throws std::runtime_error on lookup failure or malformed output.
 */
uint32_t NextHopFinder::retrieveNextHopIP(uint32_t ipDest_be) {
  struct in_addr addr   = {.s_addr = ipDest_be};
  const char* ipAddress = inet_ntoa(addr);
  if (!ipAddress) {
    throw std::runtime_error("retrieveNextHopIP: invalid destination IP");
  }
  const std::string ip_str(ipAddress);

  // Plain string concatenation: no fmt::format brace-parsing surprises.
  const std::string cmd =
      std::string("ip -o route get ") + ip_str + " 2>/dev/null";
  std::string out = CmdRunner::exec(cmd);

  Logger::upf_app().debug(
      "retrieveNextHopIP: cmd='%s' output='%s'", cmd.c_str(), out.c_str());

  if (out.empty()) {
    throw std::runtime_error(
        std::string("retrieveNextHopIP: empty route output for ") + ip_str);
  }

  // Look for the optional "via <gateway>" segment. If absent, the
  // destination is on-link and we return it as-is.
  std::istringstream iss(out);
  std::string token;
  std::string gw_str;
  while (iss >> token) {
    if (token == "via") {
      if (!(iss >> gw_str)) {
        throw std::runtime_error(
            "retrieveNextHopIP: malformed 'via' segment in route output");
      }
      break;
    }
  }

  if (gw_str.empty()) {
    // On-link: destination reachable directly, no gateway.
    Logger::upf_app().debug(
        "retrieveNextHopIP: %s is on-link, returning destination as next hop",
        ip_str.c_str());
    return ipDest_be;
  }

  const in_addr_t gw_be = inet_addr(gw_str.c_str());
  if (gw_be == INADDR_NONE) {
    throw std::runtime_error(
        std::string("retrieveNextHopIP: failed to parse gateway IP: ") +
        gw_str);
  }

  Logger::upf_app().debug(
      "retrieveNextHopIP: %s reached via gateway %s", ip_str.c_str(),
      gw_str.c_str());
  return gw_be;
}

/* ------------------------------------------------------------------------- */
/**
 * @brief Resolve the outgoing interface name for a given destination IP.
 *
 * Convenience helper used by retrieveNextHopMAC() so that ``arping`` can be
 * pinned to the correct interface (avoiding arping's default heuristic,
 * which on a multi-homed host can pick the wrong NIC).
 *
 * @param ipDest_be  Destination IP in network byte order.
 * @return interface name, or empty string if no route was found.
 */
static std::string resolveOutgoingInterface(uint32_t ipDest_be) {
  struct in_addr addr   = {.s_addr = ipDest_be};
  const char* ipAddress = inet_ntoa(addr);
  if (!ipAddress) {
    return {};
  }

  const std::string cmd = std::string("ip -o route get ") + ipAddress +
                          " 2>/dev/null | grep -oP 'dev \\K[^ ]+' | head -1";
  std::string ifname = CmdRunner::exec(cmd);
  rtrim_in_place(ifname);
  return ifname;
}

/* ------------------------------------------------------------------------- */
/**
 * @brief Resolve the link-layer (MAC) address of a next-hop IP via active
 *        ARP probing.
 *
 * The kernel ARP cache is populated reactively by traffic. Because the UPF
 * may need a downlink MAC entry **before** any UPF-originated packet has
 * traversed the N3 link, we cannot rely on the cache being warm. We use
 * ``arping`` with an explicit outgoing interface and a short retry loop
 * with backoff, giving the kernel a chance to populate its ARP cache before
 * the next attempt.
 *
 * @param nextHopIp_be  Next-hop IP in network byte order.
 * @return pointer to a statically-allocated ether_addr structure (do not
 *         free; the storage is owned by libc's ether_aton).
 * @throws std::runtime_error if ARP resolution fails after all retries.
 */
ether_addr* NextHopFinder::retrieveNextHopMAC(uint32_t nextHopIp_be) {
  struct in_addr addr   = {.s_addr = nextHopIp_be};
  const char* ipAddress = inet_ntoa(addr);
  if (!ipAddress) {
    throw std::runtime_error("retrieveNextHopMAC: invalid next-hop IP");
  }
  const std::string ip_str(ipAddress);

  // Resolve the outgoing interface from the kernel routing table to give
  // arping an explicit -I argument.
  const std::string ifname = resolveOutgoingInterface(nextHopIp_be);

  constexpr int MAX_RETRIES        = 3;
  constexpr int BACKOFF_MS         = 200;
  constexpr int ARPING_COUNT       = 2;
  constexpr int ARPING_TIMEOUT_SEC = 3;

  std::string nextHopMac;

  for (int attempt = 1; attempt <= MAX_RETRIES; ++attempt) {
    // Build the arping invocation.
    // The result is parsed via a fixed shell pipeline that extracts the
    // first MAC-address-shaped token from arping's output. We split the
    // command in two so that the log only shows the meaningful arping
    // call, not the boilerplate filter pipeline.
    std::string probe;
    std::string filter =
        " 2>&1 | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -1";

    if (!ifname.empty()) {
      probe = "arping -c " + std::to_string(ARPING_COUNT) + " -w " +
              std::to_string(ARPING_TIMEOUT_SEC) + " -I " + ifname + " " +
              ip_str;
    } else {
      // Fallback when interface lookup failed: let arping pick the iface.
      probe = "arping -c " + std::to_string(ARPING_COUNT) + " -w " +
              std::to_string(ARPING_TIMEOUT_SEC) + " " + ip_str;
    }

    const std::string cmd = probe + filter;

    Logger::upf_app().debug(
        "retrieveNextHopMAC: attempt %d/%d on iface='%s' probe='%s'", attempt,
        MAX_RETRIES, ifname.c_str(), probe.c_str());

    nextHopMac = CmdRunner::exec(cmd);
    rtrim_in_place(nextHopMac);

    if (!nextHopMac.empty()) {
      Logger::upf_app().info(
          "retrieveNextHopMAC: %s -> %s on %s (attempt %d/%d)", ip_str.c_str(),
          nextHopMac.c_str(), ifname.c_str(), attempt, MAX_RETRIES);
      break;
    }

    Logger::upf_app().warn(
        "retrieveNextHopMAC: attempt %d/%d failed for %s on iface='%s', "
        "retrying after %d ms",
        attempt, MAX_RETRIES, ip_str.c_str(), ifname.c_str(), BACKOFF_MS);

    std::this_thread::sleep_for(std::chrono::milliseconds(BACKOFF_MS));
  }

  if (nextHopMac.empty()) {
    Logger::upf_app().error(
        "retrieveNextHopMAC: ARP unresolved for %s on iface='%s' after %d "
        "attempts",
        ip_str.c_str(), ifname.c_str(), MAX_RETRIES);
    throw std::runtime_error(
        std::string("retrieveNextHopMAC: ARP unresolved for ") + ip_str);
  }

  ether_addr* mac = ether_aton(nextHopMac.c_str());
  if (!mac) {
    throw std::runtime_error(
        std::string("retrieveNextHopMAC: failed to parse MAC string '") +
        nextHopMac + "'");
  }
  return mac;
}
