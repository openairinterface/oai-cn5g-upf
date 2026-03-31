/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_SGWU_SIMPLESWITCH_HPP_SEEN
#define FILE_SGWU_SIMPLESWITCH_HPP_SEEN

#include "endpoint.hpp"
#include "gtpv1u.hpp"
#include "itti_msg_n3.hpp"
#include "msg_gtpv1u.hpp"

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <netinet/in.h>
#include <thread>

namespace oai {
namespace upf {
namespace app {

class upf_n3 : public gtpv1u::gtpu_l4_stack {
 private:
  std::thread::id thread_id;
  std::thread thread;

  void handle_receive_gtpv1u_msg(
      gtpv1u::gtpv1u_msg& msg, const endpoint& r_endpoint);
  void handle_receive_echo_request(
      gtpv1u::gtpv1u_msg& msg, const endpoint& r_endpoint);

 public:
  upf_n3();
  upf_n3(upf_n3 const&) = delete;
  void operator=(upf_n3 const&) = delete;

  // void handle_itti_msg (itti_n3_echo_request& s) {};
  void handle_itti_msg(std::shared_ptr<itti_n3_echo_response> m);
  void handle_itti_msg(std::shared_ptr<itti_n3_error_indication> m);
  // void handle_itti_msg (itti_n3_supported_extension_headers_notification& s)
  // {}; void handle_itti_msg (itti_n3_end_marker& s) {};

  // void send_msg (itti_n3_echo_request& s) {};
  // void send_msg (itti_n3_echo_response& s);
  // void send_msg (itti_n3_error_indication& s) {};
  // void send_msg (itti_n3_supported_extension_headers_notification& s) {};
  // void send_msg (itti_n3_end_marker& s) {};

  void handle_receive_n3_msg(
      gtpv1u::gtpv1u_msg& msg, const endpoint& r_endpoint);
  void handle_receive(
      char* recv_buffer, const std::size_t bytes_transferred,
      const endpoint& r_endpoint);

  void send_g_pdu(
      const struct in_addr& peer_addr, const uint16_t peer_udp_port,
      const uint32_t tunnel_id, const char* send_buffer,
      const ssize_t num_bytes, uint8_t qfi);
  void send_g_pdu(
      const struct in6_addr& peer_addr, const uint16_t peer_udp_port,
      const uint32_t tunnel_id, const char* send_buffer,
      const ssize_t num_bytes);

  void time_out_itti_event(const uint32_t timer_id);
  void report_error_indication(
      const endpoint& r_endpoint, const uint32_t tunnel_id);
};
}  // namespace app
}  // namespace upf
}  // namespace oai
#endif /* FILE_SGWU_SIMPLESWITCH_HPP_SEEN */
