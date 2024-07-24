//
// Created by root on 7/22/24.
//

#include <arpa/inet.h>
#include "LocalRoutingTest.h"

namespace fr {
TEST_F(LocalRoutingTest, AddAndDeleteRoutes) {
  const auto localRouting = std::make_shared<LocalRouting>();
  // 0xC0A80232= 192.168.2.50
  const std::string destination_adress  = "192.168.128.0";
  const int network_mask                = 24;
  const std::string device              = "tun0";
  const std::string gateway             = "12.1.1.1";
  RoutingInformation routingInformation = {
      destination_adress, network_mask, device, gateway};
  localRouting->add_route(routingInformation);
  localRouting->delete_route(0xC0A88000);
  ASSERT_NO_FATAL_FAILURE();
}
}  // namespace fr