#include "FramedRoutingTest.h"


namespace fr {
TEST_F(FramedRoutingTest, CreateFramedRoute) {
  const std::shared_ptr<fr::FramedRouting> fr =
      std::make_shared<fr::FramedRouting>();
  EXPECT_NO_FATAL_FAILURE();
}

TEST_F(FramedRoutingTest, AddRoutes) {
  auto framed_route = pfcp::framed_route_s{
      "192.168.2.10/24,192.168.1.0/24,12.1.1.1/25,192.168.1.0/25"};
  FramedRoutingTest::fr->addFramedRoute(ue_ip_one, framed_route);
  EXPECT_NO_FATAL_FAILURE();
}

TEST_F(FramedRoutingTest, AddRoutesEmptyIP) {
  auto framed_route = pfcp::framed_route_s{""};
  FramedRoutingTest::fr->addFramedRoute(ue_ip_one, framed_route);
  EXPECT_NO_FATAL_FAILURE();
}

TEST_F(FramedRoutingTest, AddRoutesDuplicates) {
  auto framed_route = pfcp::framed_route_s{"192.168.2.10/24,192.168.2.10/24"};
  FramedRoutingTest::fr->addFramedRoute(ue_ip_one, framed_route);
  EXPECT_NO_FATAL_FAILURE();
}

TEST_F(FramedRoutingTest, retrieveSubnetNotExisting) {
  const auto dest_ip = FramedRoutingTest::fr->retrieveFramedUEIp(ue_ip_one);
  EXPECT_EQ(dest_ip, 0);
}

TEST_F(FramedRoutingTest, retrieveSubnetIP) {
  auto framed_route = pfcp::framed_route_s{"192.168.2.0/25"};
  FramedRoutingTest::fr->addFramedRoute(ue_ip_one, framed_route);

  uint32_t lookup_ip = 0xc0a8027a;  // 192.168.2.122
  const auto dest_ip = FramedRoutingTest::fr->retrieveFramedUEIp(lookup_ip);

  EXPECT_EQ(dest_ip, ue_ip_one);
}
TEST_F(FramedRoutingTest, retrieveSubnetIPWrongSubnet) {
  auto framed_route = pfcp::framed_route_s{"192.168.2.10/25"};
  FramedRoutingTest::fr->addFramedRoute(ue_ip_one, framed_route);
  uint32_t lookup_ip = 0xc0a80280;
  const auto dest_ip = FramedRoutingTest::fr->retrieveFramedUEIp(lookup_ip);
  EXPECT_EQ(dest_ip, 0);
}
}  // namespace fr