//
// Created by root on 7/22/24.
//

#include <arpa/inet.h>
#include "LocalRoutingTest.h"

namespace fr {
    TEST_F(LocalRoutingTest, AddAndDeleteRoutes) {
        const auto localRouting = std::make_shared<LocalRouting>();
        // 0xC0A80232= 192.168.2.50
        const std::string destination_adress = "192.168.2.1";
        const std::string network_mask = "255.255.255.255";
        const std::string device = "tun0";
        RoutingInformation routingInformation = {destination_adress, network_mask, device};
      const bool add=  localRouting->addRoute(routingInformation);
      const bool del=  localRouting->deleteRoute(routingInformation);
        EXPECT_NO_FATAL_FAILURE();
    }
} // fr