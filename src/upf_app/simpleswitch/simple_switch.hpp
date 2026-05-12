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

/** @brief GTP-U handler for the N3 interface (UPF ↔ gNB).
 *
 *  Receives G-PDU packets from gNBs on UDP port 2152 (3GPP TS 29.281 §4.4),
 *  strips the GTP-U header, and dispatches the inner IP packet to
 *  pfcp_switch::pfcp_session_look_up_pack_in_access() for PFCP rule matching.
 *
 *  Non-G-PDU messages (Echo Request, Error Indication) are forwarded to
 *  TASK_UPF_APP via ITTI.
 */
class upf_n3 : public gtpv1u::gtpu_l4_stack {
 private:
  std::thread::id thread_id;  ///< ID of the ITTI upf_n3_task thread
  std::thread thread;         ///< Handle for the upf_n3_task ITTI thread

  //------------------------------------------------------------------------------
  /** @brief Route a non-G-PDU GTPv1-U message to the appropriate handler. */
  void handle_receive_gtpv1u_msg(
      gtpv1u::gtpv1u_msg& msg, const endpoint& r_endpoint);

  //------------------------------------------------------------------------------
  /** @brief Handle a GTP-U Echo Request (3GPP TS 29.281 §7.2.1):
   *         forward to TASK_UPF_APP for Echo Response generation.
   */
  void handle_receive_echo_request(
      gtpv1u::gtpv1u_msg& msg, const endpoint& r_endpoint);

 public:
  //------------------------------------------------------------------------------
  /** @brief Bind the GTP-U socket on N3 (UDP port 2152, 3GPP TS 29.281 §4.4)
   *  and start the TASK_UPF_N3 ITTI task loop.
   */
  upf_n3();
  upf_n3(upf_n3 const&) = delete;
  void operator=(upf_n3 const&) = delete;

  //------------------------------------------------------------------------------
  /** @brief Handle Echo Response ITTI message (3GPP TS 29.281 §7.2.2). */
  void handle_itti_msg(std::shared_ptr<itti_n3_echo_response> m);

  //------------------------------------------------------------------------------
  /** @brief Handle Error Indication ITTI message (3GPP TS 29.281 §7.3.1). */
  void handle_itti_msg(std::shared_ptr<itti_n3_error_indication> m);
  // void handle_itti_msg (itti_n3_supported_extension_headers_notification& s)
  // {}; void handle_itti_msg (itti_n3_end_marker& s) {};

  // void send_msg (itti_n3_echo_request& s) {};
  // void send_msg (itti_n3_echo_response& s);
  // void send_msg (itti_n3_error_indication& s) {};
  // void send_msg (itti_n3_supported_extension_headers_notification& s) {};
  // void send_msg (itti_n3_end_marker& s) {};

  //------------------------------------------------------------------------------
  /** @brief Dispatch a GTPv1-U message received on N3 to upf_n3 handlers. */
  void handle_receive_n3_msg(
      gtpv1u::gtpv1u_msg& msg, const endpoint& r_endpoint);

  //------------------------------------------------------------------------------
  /** @brief Entry point called by gtpu_l4_stack when a UDP datagram arrives.
   *
   *  Fast-path: G-PDU packets bypass full GTPv1-U parsing and are forwarded
   *  directly to pfcp_switch::pfcp_session_look_up_pack_in_access().
   *  All other message types go through handle_receive_gtpv1u_msg().
   *
   *  @param recv_buffer      Raw UDP payload.
   *  @param bytes_transferred Length of the UDP payload in bytes.
   *  @param r_endpoint       Source address and port of the sender.
   */
  void handle_receive(
      char* recv_buffer, const std::size_t bytes_transferred,
      const endpoint& r_endpoint);

  //------------------------------------------------------------------------------
  /** @brief Encapsulate an IPv4 packet in GTP-U and send it to a gNB (N3).
   *
   *  Builds a GTP-U G-PDU (3GPP TS 29.281 §5.1) with an optional PDU Session
   *  Container extension header carrying the QFI (3GPP TS 38.415).
   *
   *  @param peer_addr     gNB IPv4 address.
   *  @param peer_udp_port gNB GTP-U port (usually 2152).
   *  @param tunnel_id     Downlink GTP-U TEID
   *                       (3GPP TS 29.244 V17.10.0 §8.2.3 F-TEID).
   *  @param send_buffer   Inner IPv4 packet.
   *  @param num_bytes     Inner packet length in bytes.
   *  @param qfi           QoS Flow Identifier carried in PDU Session Container
   *                       (3GPP TS 29.244 V17.10.0 §8.2.89 QFI).
   */
  void send_g_pdu(
      const struct in_addr& peer_addr, const uint16_t peer_udp_port,
      const uint32_t tunnel_id, const char* send_buffer,
      const ssize_t num_bytes, uint8_t qfi);

  //------------------------------------------------------------------------------
  /** @brief Encapsulate an IPv6 packet in GTP-U and send it to a gNB (N3). */
  void send_g_pdu(
      const struct in6_addr& peer_addr, const uint16_t peer_udp_port,
      const uint32_t tunnel_id, const char* send_buffer,
      const ssize_t num_bytes);

  //------------------------------------------------------------------------------
  /** @brief ITTI timer-expiry callback (currently unused by upf_n3). */
  void time_out_itti_event(const uint32_t timer_id);

  //------------------------------------------------------------------------------
  /** @brief Send a GTP-U Error Indication to the gNB (3GPP TS 29.281 §7.3.1).
   *
   *  Called by pfcp_switch when no PFCP PDR matches the received TEID, to
   *  notify the gNB that the tunnel is unknown at this UPF.
   *
   *  @param r_endpoint  gNB source endpoint.
   *  @param tunnel_id   The TEID that was not found.
   */
  void report_error_indication(
      const endpoint& r_endpoint, const uint32_t tunnel_id);
};

}  // namespace app
}  // namespace upf
}  // namespace oai

#endif  // FILE_SGWU_SIMPLESWITCH_HPP_SEEN
