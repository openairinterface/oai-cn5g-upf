//
// Created by root on 7/22/24.
//
#pragma once

#include "LocalRouting.hpp"
#include <gmock/gmock.h>

namespace fr {
    class MockLocalRouting : public LocalRouting {
    public:
        MOCK_METHOD(void, add_route,(const RoutingInformation & routing_information),(override));
        MOCK_METHOD(void, delete_route,(const uint32_t & network_address),(override));
    };
}
