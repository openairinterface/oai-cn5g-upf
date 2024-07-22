//
// Created by root on 7/22/24.
//

#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <linux/route.h>

namespace fr {
    struct RoutingInformation {
        std::string destination;
        std::string netmask;
        std::string device;
        std::string gateway_address;
    };

    class LocalRouting {
    public:
        [[nodiscard]] bool addRoute(RoutingInformation routing_information);

        [[nodiscard]] bool deleteRoute(RoutingInformation routing_information) const;

    private:
        std::unordered_map<uint32_t, std::shared_ptr<rtentry>> routeInfoToRtEntry{};

       short getInterfaceIndex(const std::string& interfaceName);


    };

} // fr

