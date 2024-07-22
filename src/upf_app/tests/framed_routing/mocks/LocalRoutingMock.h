//
// Created by root on 7/22/24.
//
#pragma once

#include "LocalRouting.hpp"
#include <gmock/gmock.h>

namespace fr {
    class MockLocalRouting : public LocalRouting {
    public:
        MOCK_METHOD(bool, addRoute,(const RoutingInformation & routing_information),(override));
        MOCK_METHOD(bool, deleteRoute,(const uint32_t & network_address),(override));
    };
}
