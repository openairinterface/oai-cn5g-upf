/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/**
 * @file net_utils.hpp
 * @brief Network interface utility functions
 *
 * This header provides utility functions for network interface operations:
 * - Interface enumeration and counting
 * - Interface existence checks
 * - Interface index lookup
 *
 * These utilities are used during BPF program initialization to validate
 * network interfaces and retrieve interface indices for XDP attachment.
 *
 * All functions are in the oai::utils::net namespace.
 *
 * Usage:
 * @code
 * using namespace oai::utils::net;
 *
 * // Check if interface exists
 * if (!InterfaceExists("eth0")) {
 *   Logger::upf_app().error("Interface eth0 not found");
 *   return;
 * }
 *
 * // Get interface index for XDP attachment
 * int if_index = GetInterfaceIndex("eth0");
 * bpf_xdp_attach(if_index, prog_fd, flags, nullptr);
 * @endcode
 *
 * @note This implementation follows Google C++ Style Guide
 */

#ifndef NET_UTILS_HPP_
#define NET_UTILS_HPP_

#include <string>

namespace oai {
namespace utils {
namespace net {

/**
 * @brief Count the number of available network interfaces
 *
 * Enumerates all network interfaces on the system and counts those
 * that are currently UP (active).
 *
 * Uses getifaddrs() to enumerate interfaces and checks the IFF_UP flag
 * to determine if an interface is active.
 *
 * @return int Number of UP interfaces, or 0 on error
 *
 * Usage:
 * @code
 * int num_interfaces = CountAvailableInterfaces();
 * Logger::upf_app().info("Found %d active interfaces", num_interfaces);
 *
 * if (config.max_interfaces > num_interfaces) {
 *   Logger::upf_app().warn(
 *       "Configured max_interfaces (%d) exceeds available (%d)",
 *       config.max_interfaces, num_interfaces);
 * }
 * @endcode
 *
 * Common Use Cases:
 * - Validating configuration against system capabilities
 * - Determining resource allocation for per-interface maps
 * - System health checks during initialization
 *
 * @note Only counts interfaces with IFF_UP flag set
 * @note Includes loopback and virtual interfaces
 */
int CountAvailableInterfaces();

/**
 * @brief Check if a network interface exists
 *
 * Verifies that a network interface with the given name exists on
 * the system. The interface may be UP or DOWN.
 *
 * Uses if_nametoindex() which returns 0 if the interface doesn't exist.
 *
 * @param interface_name Name of the interface (e.g., "eth0", "n3", "ens0")
 * @return true if interface exists, false otherwise
 *
 * Usage:
 * @code
 * std::string gtp_interface = "n3";
 *
 * if (!InterfaceExists(gtp_interface)) {
 *   Logger::upf_app().error("GTP interface '%s' not found",
 *                           gtp_interface.c_str());
 *   throw std::runtime_error("Invalid interface configuration");
 * }
 *
 * Logger::upf_app().info("GTP interface '%s' found", gtp_interface.c_str());
 * @endcode
 *
 * Common Interface Names:
 * - Physical: eth0, ens0, enp0s3
 * - Virtual: tun0, tap0, veth0
 * - 5G UPF: n3 (GTP-U), n6 (data network), n4 (control plane)
 *
 * @note Interface may exist but be DOWN
 * @note Case-sensitive name matching
 */
bool InterfaceExists(const std::string& interface_name);

/**
 * @brief Get the kernel index of a network interface
 *
 * Retrieves the kernel's integer index for the specified interface.
 * This index is required for:
 * - XDP program attachment (bpf_xdp_attach)
 * - TC program attachment
 * - Socket binding (SO_BINDTODEVICE)
 * - Netlink operations
 *
 * Uses if_nametoindex() which is thread-safe and doesn't require
 * special privileges.
 *
 * @param interface_name Name of the interface
 * @return int Interface index (> 0), or 0 if not found
 *
 * Usage:
 * @code
 * std::string udp_interface = "eth0";
 *
 * int if_index = GetInterfaceIndex(udp_interface);
 * if (if_index == 0) {
 *   Logger::upf_app().error("Interface '%s' not found",
 *                           udp_interface.c_str());
 *   return;
 * }
 *
 * Logger::upf_app().info("Interface '%s' has index %d",
 *                        udp_interface.c_str(), if_index);
 *
 * // Use for XDP attachment
 * int ret = bpf_xdp_attach(if_index, prog_fd, XDP_FLAGS_DRV_MODE, nullptr);
 * @endcode
 *
 * Interface Index Properties:
 * - Always positive (>= 1)
 * - Persistent across interface down/up cycles
 * - May change if interface is removed and recreated
 * - Loopback (lo) is typically index 1
 *
 * @note Returns 0 if interface doesn't exist
 * @note Thread-safe
 *
 * @see if_nametoindex(3) for POSIX details
 */
int GetInterfaceIndex(const std::string& interface_name);

}  // namespace net
}  // namespace utils
}  // namespace oai

#endif  // NET_UTILS_HPP_
