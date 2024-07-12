//
// Created by root on 5/10/24.
//

#pragma once

#include <cstdint>
#include <memory>
#include <vector>
#include "FramedRoutingHash.h"
#include <folly/AtomicHashMap.h>
#include "pfcp_pdr.hpp"


namespace fr {

    class FramedRouting {
    public:
        FramedRouting() = default;

        virtual ~FramedRouting() = default;

    private:
        // todo(kw) discuss size or use constant
        std::unordered_map<FramedRoutingKey, uint32_t> KeyToIp{};

        [[nodiscard]] uint32_t framedIPToUeIP(const std::string &ip) const;

        [[nodiscard]] uint32_t frameSubnetToUInt(std::string &subnet) const;

        [[nodiscard]] std::pair<uint32_t, uint32_t> extractIPCidr(const std::string &fr_subnet) const;
        [[nodiscard]] FramedRoutingKey CreateFramedRoutingKey(const std::pair<uint32_t, uint32_t> ipCidr) const;


    public:
        [[nodiscard]] uint32_t
        retrieveFramedUEIp(const uint32_t destination_ip) const;
        void addFramedRoute(uint32_t ue_ip, const pfcp::framed_route_s &framed_route_s);
        void removeEntry(uint32_t ue_ip);

        // todo(kw) create a facade for fr options.
    };


} // fr

