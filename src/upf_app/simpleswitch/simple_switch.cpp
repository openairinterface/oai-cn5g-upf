/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "simple_switch.hpp"

#include <stdexcept>

#include "3gpp_conversions.hpp"
#include "common_defs.h"
#include "conversions.hpp"
#include "gtpu.h"
#include "itti.hpp"
#include "logger.hpp"
#include "pfcp_switch.hpp"
#include "upf_config.hpp"

using namespace gtpv1u;
using namespace oai::upf::app;
using namespace oai::config;
using namespace std;

extern itti_mw* itti_inst;
extern pfcp_switch* pfcp_switch_inst;
extern upf_config upf_cfg;
extern upf_n3* upf_n3_inst;

/** @brief ITTI task loop for N3 (GTP-U) control messages.
 *
 *  Handles N3_ECHO_RESPONSE, N3_ERROR_INDICATION, TIME_OUT, and TERMINATE
 *  ITTI message types.  G-PDU data traffic bypasses this loop and is
 *  dispatched directly in upf_n3::handle_receive() (3GPP TS 29.281 §5.1).
 *
 *  @param args_p  Pointer to oai::utils::thread_sched_params (cast from void*).
 */
void upf_n3_task(void*);

// =============================================================================
// ITTI task entry point
// =============================================================================

//------------------------------------------------------------------------------
// upf_n3_task — ITTI task loop for N3 (3GPP TS 29.281 V17.3.0).
// G-PDU data traffic is handled directly in handle_receive() without ITTI
// to avoid task-queue latency on the hot path (fast-path per §5.1).

//------------------------------------------------------------------------------
void upf_n3_task(void* args_p) {
  const task_id_t task_id = TASK_UPF_N3;

  const oai::utils::thread_sched_params* const sched_params =
      (const oai::utils::thread_sched_params* const) args_p;
  sched_params->apply(task_id, Logger::upf_n3());

  itti_inst->notify_task_ready(task_id);

  do {
    std::shared_ptr<itti_msg> shared_msg = itti_inst->receive_msg(task_id);
    auto* msg                            = shared_msg.get();
    switch (msg->msg_type) {
      case N3_ECHO_RESPONSE:
        upf_n3_inst->handle_itti_msg(
            std::static_pointer_cast<itti_n3_echo_response>(shared_msg));
        break;

      case N3_ERROR_INDICATION:
        upf_n3_inst->handle_itti_msg(
            std::static_pointer_cast<itti_n3_error_indication>(shared_msg));
        break;

      case TIME_OUT:
        if (itti_msg_timeout* to = dynamic_cast<itti_msg_timeout*>(msg)) {
          Logger::upf_n3().info("TIME-OUT event timer id %d", to->timer_id);
        }
        break;

      case TERMINATE:
        if (itti_msg_terminate* terminate =
                dynamic_cast<itti_msg_terminate*>(msg)) {
          Logger::upf_n3().info("Received terminate message");
          upf_n3_inst->stop();
          return;
        }
        break;

      case HEALTH_PING:
        break;

      default:
        Logger::upf_n3().info("no handler for msg type %d", msg->msg_type);
    }
  } while (true);
}

// =============================================================================
// Constructor
// =============================================================================

//------------------------------------------------------------------------------
upf_n3::upf_n3()
    : gtpu_l4_stack(
          upf_cfg.n3.addr4, upf_cfg.n3.port, upf_cfg.n3.thread_rd_sched_params,
          upf_cfg.enable_5g_features) {
  Logger::upf_n3().startup("Starting...");
  if (itti_inst->create_task(
          TASK_UPF_N3, upf_n3_task, &upf_cfg.itti.n3_sched_params)) {
    Logger::upf_n3().error("Cannot create task TASK_UPF_N3");
    throw std::runtime_error("Cannot create task TASK_UPF_N3");
  }
  Logger::upf_n3().startup("Started");
}

// =============================================================================
// Receive path
// =============================================================================

//------------------------------------------------------------------------------
// handle_receive — called by gtpu_l4_stack on every UDP datagram
// (3GPP TS 29.281 V17.3.0).
//
// Fast-path for G-PDU (§5.1):
//   Strip GTP-U header (min 8 bytes + optional 4-byte SN/PN/EH fields) then
//   dispatch the inner IP packet directly to pfcp_switch for PDR look-up.
//
// Slow-path for all other GTPv1-U message types:
//   Deserialise the full GTPv1-U message and route to
//   handle_receive_gtpv1u_msg().
//
// Legacy raw-IP path (gtpuh->version != 1):
//   Assume the buffer is a raw IPv4/IPv6 packet (no GTP encapsulation).

//------------------------------------------------------------------------------
void upf_n3::handle_receive(
    char* recv_buffer, const std::size_t bytes_transferred,
    const endpoint& r_endpoint) {
#define GTPU_MESSAGE_FLAGS_POS_IN_UDP_PAYLOAD 0
  // auto start = std::chrono::high_resolution_clock::now();
  struct gtpuhdr* gtpuh = (struct gtpuhdr*) &recv_buffer[0];

  if (gtpuh->version == 1) {
    // Do it fast, do not go throught handle_receive_gtpv1u_msg()
    if (gtpuh->message_type == GTPU_G_PDU) {
      // Fast-path: compute inner-payload offset without full deserialisation
      uint8_t gtp_flags = recv_buffer[GTPU_MESSAGE_FLAGS_POS_IN_UDP_PAYLOAD];
      std::size_t gtp_payload_offset = GTPV1U_MSG_HEADER_MIN_SIZE;

      // Optional fields: Sequence Number, N-PDU, Extension Header (§5.1)
      if ((((gtp_flags & GTPU_MESSAGE_VERSION_MASK)) &&
           (gtp_flags & GTPU_MESSAGE_PT_MASK)) &&
          ((gtp_flags & GTPU_MESSAGE_EXT_HEADER_MASK) ||
           (gtp_flags & GTPU_MESSAGE_SN_MASK) ||
           (gtp_flags & GTPU_MESSAGE_PN_MASK)))
        gtp_payload_offset += 4;

      std::size_t gtp_payload_length = be16toh(gtpuh->message_length);
      if (gtp_flags & 0x07) {
        // Extension header(s) present — skip PDU Session Container (4 bytes)
        gtp_payload_offset += 4;
        gtp_payload_length -= 4;
      }
      uint32_t tunnel_id = be32toh(gtpuh->teid);

      struct iphdr* iph = (struct iphdr*) &recv_buffer[gtp_payload_offset];
      if (iph->version == 4) {
        pfcp_switch_inst->pfcp_session_look_up_pack_in_access(
            iph, gtp_payload_length, r_endpoint, tunnel_id);
      } else if (iph->version == 6) {
        pfcp_switch_inst->pfcp_session_look_up_pack_in_access(
            (struct ipv6hdr*) iph, gtp_payload_length, r_endpoint, tunnel_id);
      }  // TODO [ETH-PDU] handle ETH type look up
      else {
        Logger::upf_n3().trace("Unknown GTPU_G_PDU packet");
      }
    } else {
      // Slow-path: Echo Request, Error Indication, End Marker, etc.
      std::istringstream iss(std::istringstream::binary);
      iss.rdbuf()->pubsetbuf(recv_buffer, bytes_transferred);
      gtpv1u_msg msg = {};
      try {
        msg.load_from(iss);
        handle_receive_gtpv1u_msg(msg, r_endpoint);
      } catch (gtpu_exception& e) {
        Logger::upf_n3().info("handle_receive exception %s", e.what());
      }
    }
  } else {
    // Legacy raw-IP path — no GTP encapsulation (e.g. bypass mode)
    struct iphdr* iph = (struct iphdr*) &recv_buffer[0];
    if (iph->version == 4) {
      pfcp_switch_inst->pfcp_session_look_up_pack_in_access(
          iph, bytes_transferred, r_endpoint);
    } else if (iph->version == 6) {
      pfcp_switch_inst->pfcp_session_look_up_pack_in_access(
          (struct ipv6hdr*) iph, bytes_transferred, r_endpoint);
    }  // TODO [ETH-PDU] handle ETH type look up
    else {
      Logger::upf_n3().trace("Unknown IPX packet");
    }
  }
  // auto stop = std::chrono::high_resolution_clock::now();
  // auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop
  // - start); cout << "UL took "  << duration.count() << std::endl;
}

//------------------------------------------------------------------------------
// handle_receive_gtpv1u_msg — dispatch non-G-PDU GTPv1-U messages.
// Echo Request → handle_receive_echo_request() → ITTI → TASK_UPF_APP
// All other types are silently dropped at this level.

//------------------------------------------------------------------------------
void upf_n3::handle_receive_gtpv1u_msg(
    gtpv1u_msg& msg, const endpoint& r_endpoint) {
  // Logger::upf_n3().trace( "handle_receive_gtpv1u_msg msg type %d length
  // %d", msg.get_message_type(), msg.get_message_length());
  switch (msg.get_message_type()) {
    case GTPU_ECHO_REQUEST:
      handle_receive_echo_request(msg, r_endpoint);
      break;
    case GTPU_ECHO_RESPONSE:
    case GTPU_ERROR_INDICATION:
    case GTPU_SUPPORTED_EXTENSION_HEADERS_NOTIFICATION:
    case GTPU_END_MARKER:
    case GTPU_G_PDU:
      break;
    default:
      Logger::upf_n3().error(
          "handle_receive_gtpv1u_msg unhandled msg type, length %d",
          msg.get_message_length());
  }
}

// =============================================================================
// Send helpers
// =============================================================================

//------------------------------------------------------------------------------
// send_g_pdu (IPv4) — wrap an IPv4 inner packet in a GTP-U G-PDU
// (3GPP TS 29.281 V17.3.0 §5.1) and send it to the gNB via UDP/IPv4 on N3.
// QFI (3GPP TS 29.244 V17.10.0 §8.2.89) is carried in the PDU Session
// Container extension header (3GPP TS 38.415 §5.5.2).

//------------------------------------------------------------------------------
void upf_n3::send_g_pdu(
    const struct in_addr& peer_addr, const uint16_t peer_udp_port,
    const uint32_t tunnel_id, const char* send_buffer, const ssize_t num_bytes,
    uint8_t qfi) {
  // Logger::upf_n3().info( "upf_n3::send_g_pdu() TEID " TEID_FMT " %d
  // bytes", num_bytes);
  struct sockaddr_in peer_sock_addr = {};
  peer_sock_addr.sin_family         = AF_INET;
  peer_sock_addr.sin_addr           = peer_addr;
  peer_sock_addr.sin_port           = htobe16(peer_udp_port);
  gtpu_l4_stack::send_g_pdu(
      peer_sock_addr, (teid_t) tunnel_id, send_buffer, num_bytes, qfi);
}

//------------------------------------------------------------------------------
// send_g_pdu (IPv6) — wrap an IPv6 inner packet in a GTP-U G-PDU
// (3GPP TS 29.281 V17.3.0 §5.1) and send it to the gNB via UDP/IPv6 on N3.

//------------------------------------------------------------------------------
void upf_n3::send_g_pdu(
    const struct in6_addr& peer_addr, const uint16_t peer_udp_port,
    const uint32_t tunnel_id, const char* send_buffer,
    const ssize_t num_bytes) {
  struct sockaddr_in6 peer_sock_addr = {};
  peer_sock_addr.sin6_family         = AF_INET6;
  peer_sock_addr.sin6_addr           = peer_addr;
  peer_sock_addr.sin6_port           = htobe16(peer_udp_port);
  peer_sock_addr.sin6_flowinfo       = 0;
  peer_sock_addr.sin6_scope_id       = 0;
  gtpu_l4_stack::send_g_pdu(peer_sock_addr, tunnel_id, send_buffer, num_bytes);
}

// =============================================================================
// ITTI message handlers
// =============================================================================

//------------------------------------------------------------------------------
// handle_itti_msg(echo_response) — forward Echo Response back to gNB
// (3GPP TS 29.281 §7.2.2).

//------------------------------------------------------------------------------
void upf_n3::handle_itti_msg(std::shared_ptr<itti_n3_echo_response> m) {
  send_response(m->gtp_ies);
}

//------------------------------------------------------------------------------
// handle_itti_msg(error_indication) — send Error Indication to gNB
// (3GPP TS 29.281 §7.3.1).

//------------------------------------------------------------------------------
void upf_n3::handle_itti_msg(std::shared_ptr<itti_n3_error_indication> m) {
  send_indication(m->gtp_ies);
}

//------------------------------------------------------------------------------
// handle_receive_echo_request — wrap Echo Request (3GPP TS 29.281 V17.3.0
// §7.2.1) into an ITTI message and send it to TASK_UPF_APP for response
// generation (§7.2.2).

//------------------------------------------------------------------------------
void upf_n3::handle_receive_echo_request(
    gtpv1u_msg& msg, const endpoint& r_endpoint) {
  itti_n3_echo_request* echo =
      new itti_n3_echo_request(TASK_UPF_N3, TASK_UPF_APP);

  gtpv1u_echo_request msg_ies_container = {};
  msg.to_core_type(echo->gtp_ies);

  echo->gtp_ies.r_endpoint = r_endpoint;
  echo->gtp_ies.set_teid(msg.get_teid());

  uint16_t sn = 0;
  if (msg.get_sequence_number(sn)) {
    echo->gtp_ies.set_sequence_number(sn);
  }

  std::shared_ptr<itti_n3_echo_request> secho =
      std::shared_ptr<itti_n3_echo_request>(echo);
  int ret = itti_inst->send_msg(secho);
  if (RETURNok != ret) {
    Logger::upf_n3().error(
        "Could not send ITTI message %s to task TASK_UPF_APP",
        echo->get_msg_name());
  }
}

//------------------------------------------------------------------------------
// report_error_indication — send a GTP-U Error Indication to the gNB when
// pfcp_switch receives a TEID with no matching PDR (3GPP TS 29.281 §7.3.1).
// Mandatory IEs: Tunnel Endpoint Identifier Data I (§8.3), GTP-U Peer Address.

//------------------------------------------------------------------------------
void upf_n3::report_error_indication(
    const endpoint& r_endpoint, const uint32_t tunnel_id) {
  itti_n3_error_indication* error_ind =
      new itti_n3_error_indication(TASK_UPF_N3, TASK_UPF_N3);
  error_ind->gtp_ies.r_endpoint = r_endpoint;
  error_ind->gtp_ies.set_teid(0);

  // 3GPP TS 29.281 §8.3 — Tunnel Endpoint Identifier Data I
  tunnel_endpoint_identifier_data_i_t tun_data = {};
  tun_data.tunnel_endpoint_identifier_data_i   = tunnel_id;
  error_ind->gtp_ies.set(tun_data);

  // 3GPP TS 29.281 §8.10 — GTP-U Peer Address (mandatory)
  gtp_u_peer_address_t peer_address = {};
  if (oai::utils::xgpp_conv::endpoint_to_gtp_u_peer_address(
          r_endpoint, peer_address)) {
    error_ind->gtp_ies.set(peer_address);
  } else {
    // mandatory ie
    delete error_ind;
    return;
  }

  std::shared_ptr<itti_n3_error_indication> serror_ind =
      std::shared_ptr<itti_n3_error_indication>(error_ind);
  int ret = itti_inst->send_msg(serror_ind);
  if (RETURNok != ret) {
    Logger::upf_n3().error(
        "Could not send ITTI message %s to task TASK_UPF_N3",
        error_ind->get_msg_name());
  }
}
