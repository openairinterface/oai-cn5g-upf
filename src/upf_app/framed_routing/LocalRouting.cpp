//
// Created by root on 7/22/24.
//

#include <fmt/format.h>
#include "LocalRouting.h"

namespace fr {

    bool LocalRouting::addRoute(RoutingInformation routing_information) {
        auto cmd = fmt::format(
                "ip route add {}/{} via {} dev tun0",
                routing_information.destination, routing_information.netmask,
                routing_information.gateway_address);
        auto rc = system((const char *) cmd.c_str());
        if (rc == 0) {
            return true;
        }
        return false;
    }

    bool LocalRouting::deleteRoute(RoutingInformation routing_information) const {
        auto cmd = fmt::format(
                "ip route del {}/{} via {} dev tun0",
                routing_information.destination, routing_information.netmask,
                routing_information.gateway_address);
        auto rc = system((const char *) cmd.c_str());
        if (rc == 0) {
            return true;
        }
        return false;
    }

} // fr