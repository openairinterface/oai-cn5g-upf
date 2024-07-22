//
// Created by root on 7/22/24.
//

#pragma once

#include "gtest/gtest.h"
#include "framed_routing/LocalRouting.h"



//Todo(kw) replace all tests with mocks as we do systemcalls should not be inside unit test.
namespace fr {

    class LocalRoutingTest : public testing::Test {
    protected:
        virtual void SetUp() override {}

        virtual void TearDown() override {}
    };
} // fr

