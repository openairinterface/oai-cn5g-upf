/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "DpdkPipeline.h"

#include <rte_arp.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_meter.h>
#include <rte_tcp.h>
#include <rte_ether.h>
#include <rte_gtp.h>
#include <rte_ip.h>
#include <rte_udp.h>

#include "logger.hpp"
#include "upf_network_config.h"

namespace {

/// GTP-U flags we emit: version 1, PT 1, E 1 — same as the eBPF flavour.
constexpr uint8_t kGtpFlagsWithExtension = 0x34;
/// PDU Session Container, TS 29.281 §5.2.2.7.
constexpr uint8_t kGtpNextExtPduSession = 0x85;
/// DL PDU SESSION INFORMATION, TS 38.415 §5.5.2.1.
constexpr uint8_t kPduTypeDownlink = 0;
/// QFI used when the PDR carries none.
constexpr uint8_t kDefaultQfi = 5;

/// GTP-U message types, TS 29.281 Table 6.1-1.
constexpr uint8_t kGtpMessageTypeEchoRequest  = 1;
constexpr uint8_t kGtpMessageTypeEchoResponse = 2;
constexpr uint8_t kGtpMessageTypeGPdu         = 0xFF;

/// GTP-U flags without any optional field: version 1, PT 1.
constexpr uint8_t kGtpFlagsPlain = 0x30;

/// Recovery IE, TS 29.281 §8.2: type byte plus restart counter.
constexpr uint8_t kGtpRecoveryIeType = 14;
constexpr uint16_t kGtpRecoveryIeSize = 2;

/// On the wire the PDU Session Container is 4 bytes: length, the QFI word and
/// the next-extension byte. sizeof() reports 3, because DPDK declares that
/// last byte as a flexible array member.
constexpr uint16_t kPduSessionContainerSize = 4;

/// Outer headers we add to a downlink packet.
constexpr uint16_t kEncapOverhead =
    sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + sizeof(rte_udp_hdr) +
    sizeof(rte_gtp_hdr) + sizeof(rte_gtp_hdr_ext_word) +
    kPduSessionContainerSize;

/// Gate Status values, TS 29.244 §8.2.7.
constexpr uint8_t kGateOpen = 0;

/// Outer Header Creation description bits, TS 29.244 §8.2.56.
constexpr uint16_t kOhcGtpUdpIpv4 = 0x0100;

}  // namespace

//------------------------------------------------------------------------------
DpdkPipeline::DpdkPipeline(
    const DpdkSessionTables& tables, const DpdkEgress& to_ran,
    const DpdkEgress& to_data_network)
    : tables_(tables),
      to_ran_(to_ran),
      to_data_network_(to_data_network),
      n3_local_ip_(upf::GetN3Ip()),
      n6_local_ip_(upf::GetN6Ip()) {}

//------------------------------------------------------------------------------
void DpdkPipeline::ProcessBurst(
    PortRole ingress, rte_mbuf** packets, uint16_t count, TxBatch& to_n3,
    TxBatch& to_n6) {
  for (uint16_t index = 0; index < count; ++index) {
    rte_mbuf* packet = packets[index];
    stats_.received++;

    // Give the next packet's headers a chance to arrive before we touch them.
    if (index + 1 < count) {
      rte_prefetch0(rte_pktmbuf_mtod(packets[index + 1], void*));
    }

    const Egress egress = ProcessPacket(packet, ingress);
    const bool queued   = egress == Egress::ToN3   ? to_n3.Add(packet)
                          : egress == Egress::ToN6 ? to_n6.Add(packet)
                                                   : false;
    if (!queued) {
      rte_pktmbuf_free(packet);
    }
  }
}

//------------------------------------------------------------------------------
DpdkPipeline::Egress DpdkPipeline::ProcessPacket(
    rte_mbuf* packet, PortRole ingress) {
  if (rte_pktmbuf_pkt_len(packet) <
      sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr)) {
    stats_.dropped_malformed++;
    return Egress::Drop;
  }

  rte_ether_hdr* ethernet = rte_pktmbuf_mtod(packet, rte_ether_hdr*);

  if (ethernet->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
    return HandleArp(packet, ethernet, ingress);
  }
  if (ethernet->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
    stats_.dropped_malformed++;
    return Egress::Drop;
  }

  rte_ipv4_hdr* ip = reinterpret_cast<rte_ipv4_hdr*>(ethernet + 1);

  // A GTP-U packet addressed to our own N3 address is uplink; anything else
  // is downlink traffic for a UE. On a shared port that is the only thing
  // telling the two directions apart, and in promiscuous mode we also see
  // traffic that is none of our business.
  bool looks_like_gtp = false;
  if (ip->next_proto_id == IPPROTO_UDP && ip->dst_addr == n3_local_ip_) {
    const uint16_t header_bytes = sizeof(rte_ether_hdr) +
                                  rte_ipv4_hdr_len(ip) + sizeof(rte_udp_hdr);
    if (rte_pktmbuf_data_len(packet) < header_bytes) {
      stats_.dropped_malformed++;
      return Egress::Drop;
    }
    const auto* udp = reinterpret_cast<const rte_udp_hdr*>(
        reinterpret_cast<const uint8_t*>(ip) + rte_ipv4_hdr_len(ip));
    looks_like_gtp = udp->dst_port == rte_cpu_to_be_16(RTE_GTPU_UDP_PORT);
  }

  if (looks_like_gtp && ingress != PortRole::N6) {
    return HandleUplink(packet, ip);
  }
  if (!looks_like_gtp && ingress != PortRole::N3) {
    return HandleDownlink(packet, ip);
  }

  stats_.dropped_malformed++;
  return Egress::Drop;
}

//------------------------------------------------------------------------------
// Uplink: strip the GTP-U tunnel and forward the inner packet to the DN.
//------------------------------------------------------------------------------
DpdkPipeline::Egress DpdkPipeline::HandleUplink(
    rte_mbuf* packet, rte_ipv4_hdr* outer_ip) {
  const uint8_t* packet_end =
      rte_pktmbuf_mtod(packet, const uint8_t*) + rte_pktmbuf_data_len(packet);

  uint8_t* cursor = reinterpret_cast<uint8_t*>(outer_ip) +
                    rte_ipv4_hdr_len(outer_ip) + sizeof(rte_udp_hdr);
  if (cursor + sizeof(rte_gtp_hdr) > packet_end) {
    stats_.dropped_malformed++;
    return Egress::Drop;
  }

  const rte_gtp_hdr* gtp = reinterpret_cast<const rte_gtp_hdr*>(cursor);
  cursor += sizeof(rte_gtp_hdr);

  // The optional word is present when any of E, S or PN is set (TS 29.281
  // §5.1); the extension headers then follow it as a chain.
  if (gtp->e || gtp->s || gtp->pn) {
    if (cursor + sizeof(rte_gtp_hdr_ext_word) > packet_end) {
      stats_.dropped_malformed++;
      return Egress::Drop;
    }
    uint8_t next_extension =
        reinterpret_cast<const rte_gtp_hdr_ext_word*>(cursor)->next_ext;
    cursor += sizeof(rte_gtp_hdr_ext_word);

    while (next_extension != 0) {
      if (cursor + 4 > packet_end) {
        stats_.dropped_malformed++;
        return Egress::Drop;
      }
      // Every extension header is a multiple of 4 bytes and ends with the
      // type of the next one.
      const uint16_t extension_length = static_cast<uint16_t>(cursor[0]) * 4;
      if (extension_length == 0 || cursor + extension_length > packet_end) {
        stats_.dropped_malformed++;
        return Egress::Drop;
      }
      next_extension = cursor[extension_length - 1];
      cursor += extension_length;
    }
  }

  if (gtp->msg_type == kGtpMessageTypeEchoRequest) {
    return HandleGtpEcho(
        packet, rte_pktmbuf_mtod(packet, rte_ether_hdr*), outer_ip, gtp);
  }
  if (gtp->msg_type != kGtpMessageTypeGPdu) {
    // Error Indication, End Marker and the rest belong to the control plane.
    stats_.punted++;
    return Egress::Drop;
  }

  const uint32_t teid = rte_be_to_cpu_32(gtp->teid);

  DpdkSessionRules* rules = tables_.LookupByTeid(teid);
  if (rules == nullptr) {
    stats_.dropped_no_session++;
    return Egress::Drop;
  }

  // The SDF filter applies to the UE's own packet, which starts right after
  // the tunnel headers.
  const uint16_t tunnel_length = static_cast<uint16_t>(
      cursor - rte_pktmbuf_mtod(packet, const uint8_t*));
  PacketTuple tuple;
  if (cursor + sizeof(rte_ipv4_hdr) > packet_end ||
      !ExtractTuple(
          reinterpret_cast<const rte_ipv4_hdr*>(cursor), packet_end, tuple)) {
    stats_.dropped_malformed++;
    return Egress::Drop;
  }

  const DpdkPdrEntry* entry = MatchPdr(rules->uplink_pdrs, tuple, teid, true);
  if (entry == nullptr) {
    stats_.dropped_no_rule++;
    return Egress::Drop;
  }
  const struct pfcp_pdr* pdr = &entry->pdr;

  const struct pfcp_far* far = rules->FindFar(pdr->far_id.far_id);
  if (far == nullptr) {
    stats_.dropped_no_rule++;
    return Egress::Drop;
  }
  if (far->apply_action.drop || !far->apply_action.forw) {
    stats_.dropped_action++;
    return Egress::Drop;
  }

  DpdkQerEntry* qer = rules->FindQer(pdr->qer_id.qer_id);
  if (qer != nullptr) {
    if (!GateIsOpen(qer->qer, true)) {
      stats_.dropped_action++;
      return Egress::Drop;
    }
    // The MBR applies to the UE's traffic, so charge the inner packet only.
    if (!MeterAllows(
            *qer, true, rte_pktmbuf_pkt_len(packet) - tunnel_length)) {
      stats_.dropped_rate++;
      return Egress::Drop;
    }
  }
  if (!to_data_network_.has_next_hop) {
    stats_.dropped_no_next_hop++;
    return Egress::Drop;
  }

  // Everything up to the inner packet goes away, then a fresh L2 header for
  // the data network.
  if (rte_pktmbuf_adj(packet, tunnel_length) == nullptr) {
    stats_.dropped_malformed++;
    return Egress::Drop;
  }

  rte_ether_hdr* ethernet = reinterpret_cast<rte_ether_hdr*>(
      rte_pktmbuf_prepend(packet, sizeof(rte_ether_hdr)));
  if (ethernet == nullptr) {
    stats_.dropped_no_room++;
    return Egress::Drop;
  }
  ethernet->dst_addr   = to_data_network_.next_hop;
  ethernet->src_addr   = to_data_network_.source_mac();
  ethernet->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

  __atomic_fetch_add(&rules->stats.uplink_packets, 1, __ATOMIC_RELAXED);
  __atomic_fetch_add(
      &rules->stats.uplink_bytes, rte_pktmbuf_pkt_len(packet),
      __ATOMIC_RELAXED);
  stats_.uplink_forwarded++;
  return Egress::ToN6;
}

//------------------------------------------------------------------------------
// Downlink: wrap the UE's packet in the GTP-U tunnel the FAR describes.
//------------------------------------------------------------------------------
DpdkPipeline::Egress DpdkPipeline::HandleDownlink(
    rte_mbuf* packet, rte_ipv4_hdr* inner_ip) {
  DpdkSessionRules* rules = tables_.LookupByUeIp(inner_ip->dst_addr);
  if (rules == nullptr) {
    stats_.dropped_no_session++;
    return Egress::Drop;
  }

  PacketTuple tuple;
  const uint8_t* packet_end =
      rte_pktmbuf_mtod(packet, const uint8_t*) + rte_pktmbuf_data_len(packet);
  if (!ExtractTuple(inner_ip, packet_end, tuple)) {
    stats_.dropped_malformed++;
    return Egress::Drop;
  }

  const DpdkPdrEntry* entry = MatchPdr(rules->downlink_pdrs, tuple, 0, false);
  if (entry == nullptr) {
    stats_.dropped_no_rule++;
    return Egress::Drop;
  }
  const struct pfcp_pdr* pdr = &entry->pdr;

  const struct pfcp_far* far = rules->FindFar(pdr->far_id.far_id);
  if (far == nullptr) {
    stats_.dropped_no_rule++;
    return Egress::Drop;
  }
  if (far->apply_action.drop || !far->apply_action.forw) {
    // Buffering (BAR) is not implemented, so a non-forwarding action drops.
    stats_.dropped_action++;
    return Egress::Drop;
  }

  DpdkQerEntry* qer = rules->FindQer(pdr->qer_id.qer_id);
  if (qer != nullptr) {
    if (!GateIsOpen(qer->qer, false)) {
      stats_.dropped_action++;
      return Egress::Drop;
    }
    // Charge the UE's packet, before the tunnel headers are added.
    if (!MeterAllows(
            *qer, false,
            rte_pktmbuf_pkt_len(packet) - sizeof(rte_ether_hdr))) {
      stats_.dropped_rate++;
      return Egress::Drop;
    }
  }

  const struct outer_header_creation& ohc =
      far->forwarding_parameters.outer_header_creation;
  if ((ohc.description & kOhcGtpUdpIpv4) == 0 || ohc.teid == 0) {
    // Without an F-TEID towards the RAN there is no tunnel to build.
    stats_.dropped_no_rule++;
    return Egress::Drop;
  }
  if (!to_ran_.has_next_hop) {
    stats_.dropped_no_next_hop++;
    return Egress::Drop;
  }

  // Drop the DN-side L2 header, then make room for the tunnel.
  const uint16_t inner_length =
      rte_pktmbuf_pkt_len(packet) - sizeof(rte_ether_hdr);
  if (rte_pktmbuf_adj(packet, sizeof(rte_ether_hdr)) == nullptr) {
    stats_.dropped_malformed++;
    return Egress::Drop;
  }

  uint8_t* headers = reinterpret_cast<uint8_t*>(
      rte_pktmbuf_prepend(packet, kEncapOverhead));
  if (headers == nullptr) {
    stats_.dropped_no_room++;
    return Egress::Drop;
  }

  auto* ethernet = reinterpret_cast<rte_ether_hdr*>(headers);
  ethernet->dst_addr   = to_ran_.next_hop;
  ethernet->src_addr   = to_ran_.source_mac();
  ethernet->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

  auto* outer_ip = reinterpret_cast<rte_ipv4_hdr*>(ethernet + 1);
  outer_ip->version_ihl     = RTE_IPV4_VHL_DEF;
  outer_ip->type_of_service = 0;
  outer_ip->total_length    = rte_cpu_to_be_16(
      kEncapOverhead - sizeof(rte_ether_hdr) + inner_length);
  outer_ip->packet_id       = 0;
  outer_ip->fragment_offset = 0;
  outer_ip->time_to_live    = 64;
  outer_ip->next_proto_id   = IPPROTO_UDP;
  outer_ip->src_addr        = n3_local_ip_;
  outer_ip->dst_addr        = ohc.ipv4_address.s_addr;
  outer_ip->hdr_checksum    = 0;
  outer_ip->hdr_checksum    = rte_ipv4_cksum(outer_ip);

  auto* udp = reinterpret_cast<rte_udp_hdr*>(outer_ip + 1);
  udp->src_port  = rte_cpu_to_be_16(RTE_GTPU_UDP_PORT);
  udp->dst_port  = ohc.port_number != 0 ? ohc.port_number
                                        : rte_cpu_to_be_16(RTE_GTPU_UDP_PORT);
  udp->dgram_len = rte_cpu_to_be_16(
      sizeof(rte_udp_hdr) + sizeof(rte_gtp_hdr) +
      sizeof(rte_gtp_hdr_ext_word) + kPduSessionContainerSize + inner_length);
  // Optional for IPv4 GTP-U and skipped by every UPF on the fast path.
  udp->dgram_cksum = 0;

  auto* gtp         = reinterpret_cast<rte_gtp_hdr*>(udp + 1);
  gtp->gtp_hdr_info = kGtpFlagsWithExtension;
  gtp->msg_type     = kGtpMessageTypeGPdu;
  // Everything after the mandatory 8 bytes, TS 29.281 §5.1.
  gtp->plen = rte_cpu_to_be_16(
      inner_length + sizeof(rte_gtp_hdr_ext_word) + kPduSessionContainerSize);
  gtp->teid = rte_cpu_to_be_32(ohc.teid);

  auto* extension_word = reinterpret_cast<rte_gtp_hdr_ext_word*>(gtp + 1);
  extension_word->sqn      = 0;
  extension_word->npdu     = 0;
  extension_word->next_ext = kGtpNextExtPduSession;

  auto* pdu_session =
      reinterpret_cast<rte_gtp_psc_generic_hdr*>(extension_word + 1);
  pdu_session->ext_hdr_len = 1;  // 4 bytes
  pdu_session->type        = kPduTypeDownlink;
  pdu_session->qmp         = 0;
  pdu_session->pad         = 0;
  pdu_session->spare       = 0;
  pdu_session->qfi =
      pdr->pdi.qfi.qfi != 0 ? pdr->pdi.qfi.qfi : kDefaultQfi;
  pdu_session->data[0] = 0;  // Next Extension Header Type: none

  __atomic_fetch_add(&rules->stats.downlink_packets, 1, __ATOMIC_RELAXED);
  __atomic_fetch_add(
      &rules->stats.downlink_bytes, inner_length, __ATOMIC_RELAXED);
  stats_.downlink_forwarded++;
  return Egress::ToN3;
}

//------------------------------------------------------------------------------
DpdkPipeline::Egress DpdkPipeline::HandleArp(
    rte_mbuf* packet, rte_ether_hdr* ethernet, PortRole ingress) {
  if (rte_pktmbuf_data_len(packet) <
      sizeof(rte_ether_hdr) + sizeof(rte_arp_hdr)) {
    stats_.dropped_malformed++;
    return Egress::Drop;
  }

  auto* arp = reinterpret_cast<rte_arp_hdr*>(ethernet + 1);
  if (arp->arp_opcode != rte_cpu_to_be_16(RTE_ARP_OP_REQUEST) ||
      arp->arp_protocol != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
    // Replies would feed a neighbour cache; the next hops are configured.
    stats_.punted++;
    return Egress::Drop;
  }

  // Which of our addresses is being asked about, and therefore which side
  // answers.
  const uint32_t target_ip = arp->arp_data.arp_tip;
  const DpdkEgress* egress_target = nullptr;
  Egress egress                   = Egress::Drop;

  if (target_ip == n3_local_ip_ && ingress != PortRole::N6) {
    egress_target = &to_ran_;
    egress        = Egress::ToN3;
  } else if (target_ip == n6_local_ip_ && ingress != PortRole::N3) {
    egress_target = &to_data_network_;
    egress        = Egress::ToN6;
  } else {
    stats_.punted++;
    return Egress::Drop;
  }

  // Turn the request around: the sender becomes the target, and we fill in
  // our own address as the sender.
  const rte_ether_addr requester_mac = arp->arp_data.arp_sha;
  const uint32_t requester_ip        = arp->arp_data.arp_sip;

  ethernet->dst_addr = requester_mac;
  ethernet->src_addr = egress_target->source_mac();

  arp->arp_opcode       = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
  arp->arp_data.arp_tha = requester_mac;
  arp->arp_data.arp_tip = requester_ip;
  arp->arp_data.arp_sha = egress_target->source_mac();
  arp->arp_data.arp_sip = target_ip;

  stats_.arp_replies++;
  return egress;
}

//------------------------------------------------------------------------------
DpdkPipeline::Egress DpdkPipeline::HandleGtpEcho(
    rte_mbuf* packet, rte_ether_hdr* ethernet, rte_ipv4_hdr* outer_ip,
    const rte_gtp_hdr* request) {
  if (packet->nb_segs != 1) {
    stats_.dropped_malformed++;
    return Egress::Drop;
  }

  // The response is built over the request, so the buffer must hold the
  // fixed layout we write: no optional word, one Recovery IE.
  const uint16_t response_length = sizeof(rte_ether_hdr) +
                                   sizeof(rte_ipv4_hdr) + sizeof(rte_udp_hdr) +
                                   sizeof(rte_gtp_hdr) + kGtpRecoveryIeSize;
  if (rte_pktmbuf_data_len(packet) < response_length) {
    stats_.dropped_malformed++;
    return Egress::Drop;
  }

  const rte_ether_addr peer_mac = ethernet->src_addr;
  const uint32_t peer_ip        = outer_ip->src_addr;
  const uint32_t local_ip       = outer_ip->dst_addr;
  const uint32_t teid           = request->teid;

  auto* udp_request = reinterpret_cast<const rte_udp_hdr*>(
      reinterpret_cast<const uint8_t*>(outer_ip) + rte_ipv4_hdr_len(outer_ip));
  const rte_be16_t peer_port = udp_request->src_port;

  ethernet->dst_addr = peer_mac;
  ethernet->src_addr = to_ran_.source_mac();

  // Rebuild the headers with a plain 20-byte IPv4 header, whatever the
  // request carried.
  outer_ip->version_ihl     = RTE_IPV4_VHL_DEF;
  outer_ip->type_of_service = 0;
  outer_ip->total_length    = rte_cpu_to_be_16(
      response_length - sizeof(rte_ether_hdr));
  outer_ip->packet_id       = 0;
  outer_ip->fragment_offset = 0;
  outer_ip->time_to_live    = 64;
  outer_ip->next_proto_id   = IPPROTO_UDP;
  outer_ip->src_addr        = local_ip;
  outer_ip->dst_addr        = peer_ip;
  outer_ip->hdr_checksum    = 0;
  outer_ip->hdr_checksum    = rte_ipv4_cksum(outer_ip);

  auto* udp        = reinterpret_cast<rte_udp_hdr*>(outer_ip + 1);
  udp->src_port    = rte_cpu_to_be_16(RTE_GTPU_UDP_PORT);
  udp->dst_port    = peer_port;
  udp->dgram_len   = rte_cpu_to_be_16(
      sizeof(rte_udp_hdr) + sizeof(rte_gtp_hdr) + kGtpRecoveryIeSize);
  udp->dgram_cksum = 0;

  auto* gtp         = reinterpret_cast<rte_gtp_hdr*>(udp + 1);
  gtp->gtp_hdr_info = kGtpFlagsPlain;
  gtp->msg_type     = kGtpMessageTypeEchoResponse;
  gtp->plen         = rte_cpu_to_be_16(kGtpRecoveryIeSize);
  gtp->teid         = teid;

  // Recovery IE: the restart counter is always 0 for GTP-U (TS 29.281 §8.2).
  auto* recovery = reinterpret_cast<uint8_t*>(gtp + 1);
  recovery[0]    = kGtpRecoveryIeType;
  recovery[1]    = 0;

  packet->data_len = response_length;
  packet->pkt_len  = response_length;

  stats_.gtp_echo_replies++;
  return Egress::ToN3;
}

//------------------------------------------------------------------------------
bool DpdkPipeline::ExtractTuple(
    const rte_ipv4_hdr* ip, const uint8_t* packet_end, PacketTuple& tuple) {
  const uint8_t* layer4 =
      reinterpret_cast<const uint8_t*>(ip) + rte_ipv4_hdr_len(ip);
  if (layer4 > packet_end) return false;

  tuple.source_address      = ip->src_addr;
  tuple.destination_address = ip->dst_addr;
  tuple.protocol            = ip->next_proto_id;

  // Only TCP and UDP carry ports; for anything else they stay 0, which is what
  // a filter with no port range expects.
  if (ip->next_proto_id == IPPROTO_UDP) {
    if (layer4 + sizeof(rte_udp_hdr) > packet_end) return false;
    const auto* udp        = reinterpret_cast<const rte_udp_hdr*>(layer4);
    tuple.source_port      = rte_be_to_cpu_16(udp->src_port);
    tuple.destination_port = rte_be_to_cpu_16(udp->dst_port);
  } else if (ip->next_proto_id == IPPROTO_TCP) {
    if (layer4 + sizeof(rte_tcp_hdr) > packet_end) return false;
    const auto* tcp        = reinterpret_cast<const rte_tcp_hdr*>(layer4);
    tuple.source_port      = rte_be_to_cpu_16(tcp->src_port);
    tuple.destination_port = rte_be_to_cpu_16(tcp->dst_port);
  }

  return true;
}

namespace {

/**
 * @brief Does the packet fall inside this SDF filter?
 *
 * The parser keeps the address in the low 32 bits of its 128-bit field and the
 * prefix mask in the high 32 bits, both in host order, so they are converted
 * before meeting the packet's network-order addresses. This is the same
 * arithmetic the eBPF flavour performs, so both agree on what a filter means.
 */
bool SdfMatches(
    const struct sdf_filtr& sdf, const DpdkPipeline::PacketTuple& tuple) {
  const uint32_t filter_source_address =
      rte_cpu_to_be_32(static_cast<uint32_t>(sdf.src_addr.ip));
  const uint32_t filter_source_mask =
      rte_cpu_to_be_32(static_cast<uint32_t>(sdf.src_addr.mask >> 96));
  const uint32_t filter_destination_address =
      rte_cpu_to_be_32(static_cast<uint32_t>(sdf.dst_addr.ip));
  const uint32_t filter_destination_mask =
      rte_cpu_to_be_32(static_cast<uint32_t>(sdf.dst_addr.mask >> 96));

  return (sdf.protocol == 0 || sdf.protocol == tuple.protocol) &&
         (tuple.source_address & filter_source_mask) == filter_source_address &&
         (tuple.destination_address & filter_destination_mask) ==
             filter_destination_address &&
         tuple.source_port >= sdf.src_port.lower_bound &&
         tuple.source_port <= sdf.src_port.upper_bound &&
         tuple.destination_port >= sdf.dst_port.lower_bound &&
         tuple.destination_port <= sdf.dst_port.upper_bound;
}

/**
 * @brief How narrow a filter is, so the tightest match wins.
 *
 * Same scoring as the eBPF flavour: an exact protocol counts most, then the
 * bits set in the address masks, then how narrow the port ranges are.
 */
uint32_t SdfSpecificity(const struct sdf_filtr& sdf, uint8_t packet_protocol) {
  uint32_t score = sdf.protocol == 0                 ? 100
                   : sdf.protocol == packet_protocol ? 300
                                                     : 50;

  score += __builtin_popcount(static_cast<uint32_t>(sdf.src_addr.mask >> 96));
  score += __builtin_popcount(static_cast<uint32_t>(sdf.dst_addr.mask >> 96));

  const uint16_t source_span =
      sdf.src_port.upper_bound - sdf.src_port.lower_bound;
  const uint16_t destination_span =
      sdf.dst_port.upper_bound - sdf.dst_port.lower_bound;
  if (source_span < UINT16_MAX) score += (UINT16_MAX - source_span) / 1000;
  if (destination_span < UINT16_MAX) {
    score += (UINT16_MAX - destination_span) / 1000;
  }

  return score;
}

}  // namespace

//------------------------------------------------------------------------------
const DpdkPdrEntry* DpdkPipeline::MatchPdr(
    const std::vector<DpdkPdrEntry>& candidates, const PacketTuple& tuple,
    uint32_t teid, bool uplink) {
  const DpdkPdrEntry* best      = nullptr;
  uint32_t best_specificity     = 0;
  const DpdkPdrEntry* catch_all = nullptr;

  for (const auto& entry : candidates) {
    // An uplink PDR is tied to the tunnel the packet arrived on.
    if (uplink && entry.pdr.pdi.fteid.teid != 0 &&
        entry.pdr.pdi.fteid.teid != teid) {
      continue;
    }

    if (!entry.has_sdf) {
      // The list is precedence-ordered, so the first one is the best catch-all.
      if (catch_all == nullptr) catch_all = &entry;
      continue;
    }

    if (!SdfMatches(entry.sdf, tuple)) continue;

    const uint32_t specificity = SdfSpecificity(entry.sdf, tuple.protocol);
    if (best == nullptr || specificity > best_specificity) {
      best             = &entry;
      best_specificity = specificity;
    }
  }

  return best != nullptr ? best : catch_all;
}

//------------------------------------------------------------------------------
bool DpdkPipeline::GateIsOpen(const struct pfcp_qer& qer, bool uplink) {
  return (uplink ? qer.gate_status.ul_gate : qer.gate_status.dl_gate) ==
         kGateOpen;
}

//------------------------------------------------------------------------------
bool DpdkPipeline::MeterAllows(
    DpdkQerEntry& qer, bool uplink, uint32_t packet_length) {
  const bool metered = uplink ? qer.meters_uplink : qer.meters_downlink;
  if (!metered) return true;  // This direction has no MBR.

  rte_meter_srtcm_profile& profile =
      uplink ? qer.uplink_profile : qer.downlink_profile;
  rte_meter_srtcm& meter = uplink ? qer.uplink_meter : qer.downlink_meter;
  rte_spinlock_t& lock   = uplink ? qer.uplink_lock : qer.downlink_lock;

  // The bucket is shared with any other lcore carrying this session, and a
  // check both reads and refills it.
  rte_spinlock_lock(&lock);
  const rte_color color = rte_meter_srtcm_color_blind_check(
      &meter, &profile, rte_rdtsc(), packet_length);
  rte_spinlock_unlock(&lock);

  return color == RTE_COLOR_GREEN;
}
