//
// Created by root on 7/22/24.
//

#pragma once

#include <memory>
#include <string>
#include <unordered_map>

namespace fr {
    struct RoutingInformation {
        std::string destination;
        uint32_t netmask;
        std::string device;
        std::string gateway_address;
    };
//todo (kw) rename class
    class LocalRouting {
    public:
        [[nodiscard]] virtual bool addRoute(const RoutingInformation &routing_information);

        [[nodiscard]] virtual bool deleteRoute(const uint32_t & network_address);

    private:

        std::unordered_map<std::string, RoutingInformation> routeInfoToRtEntry{};


       short getInterfaceIndex(const std::string& interfaceName);


    };

} // fr

