//
// Created by root on 6/21/24.
//

#pragma once

#include <memory>
#include <tests/framed_routing/mocks/LocalRoutingMock.h>
#include "framed_routing/FramedRouting.hpp"
#include "gtest/gtest.h"



namespace fr {
    class FramedRoutingTest : public testing::Test {
    protected:
        virtual void SetUp() override {}

        virtual void TearDown() override {}

    public:
        const std::shared_ptr<MockLocalRouting> local_routing = std::make_shared<MockLocalRouting>();
        const uint32_t ue_ip_one = 0x20010102;  // 12.1.1.2
        const std::shared_ptr<fr::FramedRouting> fr =
                std::make_shared<fr::FramedRouting>(local_routing);
    };
}  // namespace fr