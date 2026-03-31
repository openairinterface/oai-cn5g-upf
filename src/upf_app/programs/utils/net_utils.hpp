/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */
#pragma once
#include <string>

namespace oai::utils::net {

int count_available_interfaces();
bool interface_exists(const std::string& ifname);
int get_interface_index(const std::string& ifname);

}  // namespace oai::utils::net
