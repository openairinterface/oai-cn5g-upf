/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "pfcp_switch.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <stdexcept>
#include <unordered_map>
#include <vector>
#include <fcntl.h>
#include <poll.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#include "common_defs.h"
#include "itti.hpp"
#include "logger.hpp"
#include "qos_mbr.hpp"
#include "simple_switch.hpp"
#include "upf_config.hpp"
#include "upf_n4.hpp"
#include "upf_pfcp_association.hpp"

std::shared_ptr<SessionManager> session_manager;

using namespace pfcp;
using namespace gtpv1u;
using namespace oai::config;
using namespace oai::upf::app;
using namespace std;

extern itti_mw* itti_inst;
extern upf_config upf_cfg;
extern upf_n3* upf_n3_inst;
extern upf_n4* upf_n4_inst;  // Usage Reports are sent over N4
extern pfcp_switch* pfcp_switch_inst;

namespace {
// A full table drops the rule without a word, and the miss only shows up later
// as traffic that matches nothing. Say so where it happens.
template<typename Map, typename Key, typename Val>
void insert_or_error(Map& map, const Key key, Val val, const char* what) {
  if (!map.insert(key, std::move(val)))
    Logger::pfcp_switch().error(
        "%s table is full: 0x%lx not installed, its packets will match no rule",
        what, (unsigned long) key);
}

// --- checksums, for the segments this code builds itself ---------------------
// Only needed on the GSO path: a segment the kernel did not create has no
// checksum of its own, and the inner header travels end to end inside GTP-U,
// so it has to be right here. This is work the kernel would otherwise have
// done while segmenting, not extra work.

/// Sum @p len bytes into a 32-bit accumulator, ones-complement style.
inline uint32_t csum_partial(const void* p, size_t len, uint32_t sum) {
  const auto* b = (const uint8_t*) p;
  while (len > 1) {
    uint16_t w;
    memcpy(&w, b, 2);
    sum += w;
    b += 2;
    len -= 2;
  }
  if (len) sum += *b;  // odd trailing byte, already in network order
  return sum;
}

inline uint16_t csum_fold(uint32_t sum) {
  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
  return (uint16_t) ~sum;
}

/// IPv4 header checksum, over the header only (§RFC 791).
inline void ip_csum_set(struct iphdr* iph) {
  iph->check = 0;
  iph->check = csum_fold(csum_partial(iph, (size_t) iph->ihl * 4, 0));
}

/// TCP checksum over the pseudo-header plus the segment (§RFC 793).
inline void tcp_csum_set(struct iphdr* iph, size_t l4_len) {
  auto* th   = (struct tcphdr*) ((uint8_t*) iph + (size_t) iph->ihl * 4);
  th->check  = 0;
  uint32_t s = 0;
  s          = csum_partial(&iph->saddr, 4, s);
  s          = csum_partial(&iph->daddr, 4, s);
  const uint16_t proto_be = htons(IPPROTO_TCP);
  const uint16_t len_be   = htons((uint16_t) l4_len);
  s                       = csum_partial(&proto_be, 2, s);
  s                       = csum_partial(&len_be, 2, s);
  s                       = csum_partial(th, l4_len, s);
  th->check               = csum_fold(s);
}

/// @brief Finish a checksum the kernel deliberately left incomplete.
///
/// TUN_F_CSUM has to be advertised to get TSO, and it also stops the kernel
/// checksumming the packets it does *not* split. Those arrive with NEEDS_CSUM
/// set and the two bytes at csum_start+csum_offset holding the pseudo-header
/// sum instead of a finished checksum. Forwarding one unchanged puts a packet
/// on the air that every receiver counts as a bad segment and discards.
///
/// That partial sum lies inside the range being summed, so summing
/// [csum_start, end) and folding picks it up: the field must be read as part
/// of the data, never cleared first.
inline void vnet_complete_csum(
    char* pkt, size_t plen, uint16_t csum_start, uint16_t csum_offset) {
  const size_t at = (size_t) csum_start + csum_offset;
  if (csum_start >= plen || at + sizeof(uint16_t) > plen) return;  // malformed
  const uint16_t c =
      csum_fold(csum_partial(pkt + csum_start, plen - csum_start, 0));
  memcpy(pkt + at, &c, sizeof(c));
}

//------------------------------------------------------------------------------
// The shaper's queue: what a packet that is over rate waits in until the slot
// its meter reserved for it comes round.
//
// One per datapath thread, reached through a thread_local, so there is no lock
// and no sharing: the thread that queued a packet is the thread that releases
// it, and a flow is only ever on one thread. The rates themselves stay shared
// (see qos_bucket), which is what keeps a session AMBR exact across threads
// without any of them having to own it.
//
// Storage is one slab taken the first time a thread shapes anything. Nothing
// is allocated on the packet path, and when the slab is full the packet is
// dropped -- a shaper with an unbounded queue is just latency with extra
// steps.
//------------------------------------------------------------------------------
constexpr size_t SHAPER_SLOTS = 1024;

struct shaped_packet {
  uint64_t due;   ///< ns, steady_clock: when this packet may be sent
  uint32_t slot;  ///< index into the slab
  uint32_t len;
  uint32_t teid;  ///< uplink: the tunnel it arrived on. 0 means downlink.
  endpoint peer;  ///< uplink: the gNB it came from, for the rule match
};

/// Later departures sort last, so the vector is a min-heap on `due`.
struct shaped_later {
  bool operator()(const shaped_packet& a, const shaped_packet& b) const {
    return a.due > b.due;
  }
};

struct shaper_queue {
  std::vector<char> slab;
  std::vector<uint32_t> free_slots;
  std::vector<shaped_packet> heap;
  /// Only this thread writes them; the logger reads them from another.
  std::atomic<uint64_t> held{0}, dropped{0}, queued{0}, late_max{0};

  shaper_queue();
  ~shaper_queue();

  /// Where a packet sits in its slot: after the room send_g_pdu() needs to
  /// write the GTP-U header in front of it, exactly like a receive buffer, so
  /// releasing one costs no second copy.
  char* payload(uint32_t slot) {
    return slab.data() + (size_t) slot * PFCP_SWITCH_RECV_BUFFER_SIZE +
           ROOM_FOR_GTPV1U_G_PDU;
  }
  static constexpr size_t capacity =
      PFCP_SWITCH_RECV_BUFFER_SIZE - ROOM_FOR_GTPV1U_G_PDU;

  bool has_room() const { return !free_slots.empty(); }

  bool hold(
      const char* pkt, size_t len, uint64_t due, uint32_t teid,
      const endpoint* peer) {
    if (free_slots.empty() || len > capacity) return false;
    const uint32_t slot = free_slots.back();
    free_slots.pop_back();
    memcpy(payload(slot), pkt, len);
    heap.push_back(
        {due, slot, (uint32_t) len, teid, peer ? *peer : endpoint()});
    std::push_heap(heap.begin(), heap.end(), shaped_later());
    held.fetch_add(1, std::memory_order_relaxed);
    queued.store(heap.size(), std::memory_order_relaxed);
    return true;
  }

  void drop() { dropped.fetch_add(1, std::memory_order_relaxed); }
};

/// Every queue that currently exists, so the queue-balance line can report
/// them without any of the threads knowing its own index. A queue is
/// thread_local, so it goes away when its thread does and has to come off this
/// list with it -- otherwise the logger, which runs on another thread, reads
/// through a pointer into storage that has been freed.
std::mutex shaper_reg_mu;
std::vector<shaper_queue*> shaper_reg;

/// What the queues that have gone contributed, so the totals do not fall when
/// a worker exits. `queued` is deliberately absent: a queue that no longer
/// exists is holding nothing.
std::atomic<uint64_t> shaper_gone_held{0};
std::atomic<uint64_t> shaper_gone_dropped{0};
std::atomic<uint64_t> shaper_gone_late{0};

shaper_queue::shaper_queue() {
  slab.resize(SHAPER_SLOTS * PFCP_SWITCH_RECV_BUFFER_SIZE);
  free_slots.reserve(SHAPER_SLOTS);
  heap.reserve(SHAPER_SLOTS);
  for (uint32_t i = 0; i < SHAPER_SLOTS; i++) free_slots.push_back(i);
  std::lock_guard<std::mutex> lk(shaper_reg_mu);
  shaper_reg.push_back(this);
}

shaper_queue::~shaper_queue() {
  std::lock_guard<std::mutex> lk(shaper_reg_mu);
  shaper_gone_held.fetch_add(
      held.load(std::memory_order_relaxed), std::memory_order_relaxed);
  shaper_gone_dropped.fetch_add(
      dropped.load(std::memory_order_relaxed), std::memory_order_relaxed);
  const uint64_t w = late_max.load(std::memory_order_relaxed);
  uint64_t seen    = shaper_gone_late.load(std::memory_order_relaxed);
  while (w > seen &&
         !shaper_gone_late.compare_exchange_weak(
             seen, w, std::memory_order_relaxed, std::memory_order_relaxed)) {
  }
  shaper_reg.erase(
      std::remove(shaper_reg.begin(), shaper_reg.end(), this),
      shaper_reg.end());
}

shaper_queue& shaper() {
  static thread_local shaper_queue q;
  return q;
}

/// Whether this thread shapes at all. Armed on the first packet it meters, so
/// no thread that never shapes ever builds a slab.
thread_local bool shaping_ = false;
}  // namespace

// =============================================================================
// PDN I/O thread
// =============================================================================

//------------------------------------------------------------------------------
// pdn_read_loop — DL datapath thread.
// Reads IP packets from tun0 and forwards each one inline: PDR look-up, FAR,
// GTP-U encapsulation and send.  One thread, no queue.

//------------------------------------------------------------------------------
// segment_and_forward -- split one GSO super-packet into MTU-sized packets.
//
// The kernel hands over a single TCP segment of up to 64 kB together with the
// MSS it was built for, and leaves the splitting to whoever asked for
// TUNSETOFFLOAD. Each piece needs the original headers, its own sequence
// number, its own IP ID and its own checksums -- precisely the work the kernel
// does in tcp_gso_segment(), moved here so it costs one syscall instead of
// forty-odd.
//
// Anything not understood is forwarded whole: it is a valid packet either way,
// and passing it through is always safer than dropping it.
//
// `off` is the cursor into the payload: it comes in 0 and goes out equal to
// `plen` when the packet is done. A 64 kB super-packet with a small MSS needs
// more segments than one send batch has slots, so when the slots run out the
// caller flushes the batch and calls again from the cursor. Every path that
// gives up on a packet sets the cursor to `plen`, so the caller's loop always
// terminates.
//
// @returns how many slots were filled.
int pfcp_switch::segment_and_forward(
    const char* pkt, std::size_t plen, const struct upf_vnet_hdr& vnet,
    char** slot, ssize_t* slot_len, int max_slots, std::size_t slot_capacity,
    std::size_t& off) {
  if (max_slots <= 0) return 0;  // no room left; the cursor stands still
  const auto give_up = [&off, plen]() { off = plen; };

  const auto* iph  = (const struct iphdr*) pkt;
  const size_t mss = vnet.gso_size;

  // Only IPv4 TCP is split here. IPv6 and everything else falls through to the
  // copy below, which still forwards the packet correctly.
  const bool splittable = plen >= sizeof(struct iphdr) && iph->version == 4 &&
                          iph->protocol == IPPROTO_TCP && mss > 0 &&
                          (vnet.gso_type == UPF_VNET_HDR_GSO_TCPV4 ||
                           vnet.gso_type == UPF_VNET_HDR_GSO_NONE);

  // Pass it on unchanged. Right for a packet that is already one segment, and
  // the only thing that can be done with one this cannot read.
  const auto forward_whole = [&]() {
    give_up();
    if (plen > slot_capacity) {
      Logger::pfcp_switch().warn(
          "downlink: %zu-byte packet (gso_type %u) does not fit a %zu-byte "
          "slot and cannot be split, dropped",
          plen, (unsigned) vnet.gso_type, slot_capacity);
      return 0;
    }
    memcpy(slot[0], pkt, plen);
    slot_len[0] = (ssize_t) plen;
    return 1;
  };

  if (!splittable) return forward_whole();

  const size_t ihl = (size_t) iph->ihl * 4;
  if (plen < ihl + sizeof(struct tcphdr)) return forward_whole();
  const auto* th   = (const struct tcphdr*) (pkt + ihl);
  const size_t thl = (size_t) th->doff * 4;
  const size_t hdr = ihl + thl;
  if (plen <= hdr || hdr + mss > slot_capacity) return forward_whole();

  // Anything longer than one segment has to be split even when it would fit a
  // slot: a slot holds 1984 bytes, so a two-segment super-packet used to go out
  // whole, and the kernel then fragmented it on the N3 link. That doubles the
  // packet rate downlink and is invisible from here -- it shows up only as
  // Ip/FragOKs climbing at the packet rate.
  if (plen <= hdr + mss) return forward_whole();

  const size_t body   = plen - hdr;
  const uint32_t seq0 = ntohl(th->seq);
  const uint16_t id0  = ntohs(iph->id);

  int filled = 0;
  for (; off < body && filled < max_slots; off += mss) {
    const size_t chunk = std::min(mss, body - off);
    const bool last    = (off + chunk >= body);
    char* out          = slot[filled];
    memcpy(out, pkt, hdr);                      // headers
    memcpy(out + hdr, pkt + hdr + off, chunk);  // this segment's payload

    auto* oiph    = (struct iphdr*) out;
    auto* oth     = (struct tcphdr*) (out + ihl);
    oiph->tot_len = htons((uint16_t) (hdr + chunk));
    // A distinct ID per segment: they are separate datagrams on the wire and
    // sharing one ID breaks any receiver that reassembles by it.
    oiph->id = htons((uint16_t) (id0 + off / mss));
    oth->seq = htonl(seq0 + (uint32_t) off);
    if (!last) {
      // Only the final segment carries end-of-data markers.
      oth->fin = 0;
      oth->psh = 0;
    }
    ip_csum_set(oiph);
    tcp_csum_set(oiph, thl + chunk);

    slot_len[filled] = (ssize_t) (hdr + chunk);
    ++filled;
  }
  if (off >= body) give_up();  // nothing of this packet is left
  return filled;
}

//------------------------------------------------------------------------------
void pfcp_switch::pdn_read_loop(
    int sock_r, int idx, oai::utils::thread_sched_params sched_params) {
  uint64_t errors = 0;

  if (idx == 0) prThreadToCancel = pthread_self();
  sched_params.apply(TASK_NONE, Logger::pfcp_switch());

  // This thread owns tun queue `idx` and is the only reader of it. The kernel
  // steers a flow to one queue and keeps it there, so every packet of a flow
  // is handled by this one thread and cannot overtake itself. Several threads
  // sharing one queue -- what this replaced -- reordered ~17% of packets.
  //
  // The buffers keep ROOM_FOR_GTPV1U_G_PDU of headroom in front so that
  // send_g_pdu() can write the GTP-U header in place without a copy. The
  // transmit side is batched -- drain up to DL_BATCH packets, encapsulate them
  // all, then hand the lot to one sendmmsg(). Every queued buffer has to stay
  // untouched until that flush, which is why each packet needs a slot of its
  // own rather than one shared scratch buffer.
  constexpr int DL_BATCH = UDP_TX_BATCH;
  const size_t payload_capacity =
      PFCP_SWITCH_RECV_BUFFER_SIZE - ROOM_FOR_GTPV1U_G_PDU;
  std::vector<char> bufs((size_t) DL_BATCH * PFCP_SWITCH_RECV_BUFFER_SIZE);
  char* payload[DL_BATCH];
  ssize_t len[DL_BATCH];
  for (int i = 0; i < DL_BATCH; i++)
    payload[i] = bufs.data() + (size_t) i * PFCP_SWITCH_RECV_BUFFER_SIZE +
                 ROOM_FOR_GTPV1U_G_PDU;

  // With IFF_VNET_HDR every read is prefixed by this header, and when it says
  // GSO the packet that follows can be up to 64 kB -- far more than one slot
  // holds. The read therefore scatters into [slot, spill]: an ordinary packet
  // lands wholly in the slot and is forwarded with no copy at all, exactly as
  // before. Only an oversized one reaches `spill`, and then the slot's share is
  // copied to the front of `spill` so the segmenter sees one contiguous packet.
  // That copy is once per super-packet, not once per segment.
  constexpr size_t GSO_MAX = 65536 + 128;
  std::vector<char> spill(payload_capacity + GSO_MAX);
  struct upf_vnet_hdr vnet = {};

  // The fd is O_NONBLOCK, so the drain below costs one read() per packet and
  // nothing else. It used to poll() before every read to decide whether more
  // was queued -- two syscalls per packet instead of one -- because the fd had
  // to stay blocking for send_to_core()'s writes. Those now retry on EAGAIN
  // instead, which costs nothing until the queue is actually full.
  struct pollfd pfd = {};
  pfd.fd            = sock_r;
  pfd.events        = POLLIN;

  const int q   = idx < TUN_MAX_QUEUES ? idx : TUN_MAX_QUEUES - 1;
  auto last_log = std::chrono::steady_clock::now();
  // This thread's shaping queue, if the downlink shapes at all. Touching it
  // here also builds it now rather than on the first packet that needs it.
  if (upf_cfg.enable_qos && upf_cfg.qos_shape_ms) {
    shaper();  // build the slab now rather than on the first packet
    shaping_ = true;
  }

  // Encapsulate and send whatever is queued. Normally once per batch, but also
  // mid-batch when a GSO super-packet needs more slots than are left.
  const auto forward_batch = [&](int count) {
    if (count <= 0) return;
    tun_q_[q].rx.fetch_add((uint64_t) count, std::memory_order_relaxed);
    for (int i = 0; i < count; i++)
      pfcp_session_look_up_pack_in_core(payload[i], len[i]);
    if (upf_n3_inst) upf_n3_inst->flush_tx_batch();
  };
  // Send this queue's traffic on the matching N3 socket, so downlink thread q
  // and uplink receive thread q share one socket and no two threads share any.
  if (upf_n3_inst) upf_n3_inst->begin_tx_batch(q);

  while (1) {
    // One clock read per batch, on one thread only. It has to be here rather
    // than after the batch: this thread only sees a flow the hash sent to its
    // queue, so it can sit in poll() indefinitely while the others are busy --
    // which is exactly when the balance is worth logging.
    if (q == 0) {
      const auto now = std::chrono::steady_clock::now();
      if (now - last_log >= std::chrono::seconds(10)) {
        last_log = now;
        log_tun_queue_balance();
      }
    }

    int n         = 0;  // slots filled with ready-to-forward packets
    bool gso_seen = false;
    while (n < DL_BATCH) {
      struct iovec iov[3];
      iov[0].iov_base = &vnet;
      iov[0].iov_len  = sizeof(vnet);
      iov[1].iov_base = payload[n];
      iov[1].iov_len  = payload_capacity;
      iov[2].iov_base = spill.data() + payload_capacity;
      iov[2].iov_len  = GSO_MAX;

      ssize_t r = readv(sock_r, iov, 3);
      if (r > 0) {
        const size_t plen = (size_t) r - sizeof(vnet);
        if (plen <= payload_capacity &&
            vnet.gso_type == UPF_VNET_HDR_GSO_NONE) {
          // Ordinary packet, already in its slot: no copy, no segmenting. It
          // may still need its checksum finishing -- see vnet_complete_csum().
          if (vnet.flags & UPF_VNET_HDR_F_NEEDS_CSUM)
            vnet_complete_csum(
                payload[n], plen, vnet.csum_start, vnet.csum_offset);
          len[n++] = (ssize_t) plen;
          continue;
        }
        // Oversized, or flagged as a segment the kernel did not split. Make it
        // contiguous at the front of `spill`, then fan it out into the slots.
        // It has already been read off the tun, so it is this thread's only
        // copy: when it needs more slots than the batch has left, send what is
        // there and carry on from the cursor rather than lose the tail.
        memcpy(spill.data(), payload[n], payload_capacity);
        gso_seen = true;
        for (std::size_t off = 0; off < plen;) {
          n += segment_and_forward(
              spill.data(), plen, vnet, payload + n, len + n, DL_BATCH - n,
              payload_capacity, off);
          if (off < plen) {
            forward_batch(n);
            n = 0;
          }
        }
        continue;
      }
      if (r < 0 && errno == EINTR) continue;
      if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
      ++errors;
      Logger::pfcp_switch().error(
          "readv failed rc=%d:%s nb_errors %d", r, strerror(errno), errors);
      std::this_thread::sleep_for(std::chrono::milliseconds(1000));
      exit(0);
    }

    if (n == 0) {
      // Nothing queued. Anything already encapsulated has been flushed by the
      // previous iteration, so it is safe to sleep here. The timeout exists so
      // an idle queue-0 thread still reaches the logging above -- and, when
      // the shaper is holding something, so that this thread wakes for the
      // slot it reserved. ppoll() rather than poll() because a millisecond of
      // rounding is a millisecond of rate at stake, and because the wait has
      // to be shortened, never lengthened.
      int64_t wait_ns       = release_shaped();
      const int64_t idle_ns = q == 0 ? 1000000000LL : -1;
      if (wait_ns < 0) wait_ns = idle_ns;
      if (idle_ns >= 0 && idle_ns < wait_ns) wait_ns = idle_ns;
      if (wait_ns < 0) {
        ppoll(&pfd, 1, nullptr, nullptr);
      } else {
        struct timespec ts = {
            (time_t) (wait_ns / 1000000000LL), (long) (wait_ns % 1000000000LL)};
        ppoll(&pfd, 1, &ts, nullptr);
      }
      continue;
    }
    (void) gso_seen;

    forward_batch(n);
    release_shaped();
  }
}

//------------------------------------------------------------------------------
// release_shaped -- forward every held packet whose slot has come.
//
// Called once per batch and again before the thread waits, so a queue is never
// left holding a packet that is already due. The rule is looked up again
// rather than remembered: a session can be modified or deleted while a packet
// waits, and a pointer kept across that wait is a pointer to a rule that may
// be gone.
//------------------------------------------------------------------------------
// meter -- charge one packet to its rates, and hold it if it has to wait.
//
// Returns false when the caller must let this packet go: either the rate said
// no, or it said "later" and there was nowhere to keep it. `teid` and `peer`
// are what the uplink needs to find its rule again at release; the downlink
// finds it from the packet's own address and passes 0.
//------------------------------------------------------------------------------
bool pfcp_switch::meter(
    oai::upf::qos_mbr& qos, const char* pkt, std::size_t len, uint32_t teid,
    const endpoint* peer) {
  // An uplink thread arms itself here: it is not the one that runs the
  // downlink loop, and it only ever needs a queue if this direction shapes.
  if (!shaping_ && teid && upf_cfg.qos_shape_ul_ms) {
    shaper();
    shaping_ = true;
  }
  // Whether this thread could hold the packet at all: the slab is the hard
  // ceiling behind the time horizon.
  const bool may_wait = shaping_ && shaper().has_room();
  const uint64_t due  = qos.due_at(len, may_wait);
  if (due == oai::upf::QOS_TOO_LATE) {
    if (shaping_) shaper().drop();
    return false;
  }
  if (!due) return true;  // inside its rate: send it now
  if (!shaper().hold(pkt, len, due, teid, peer)) shaper().drop();
  return false;  // held, or dropped for want of a slot; either way not now
}

//------------------------------------------------------------------------------
// release_shaped -- forward every held packet whose slot has come, and say how
// long until the next one is due.
//
// Called once per batch and again before the thread waits, so a queue is never
// left holding a packet that is already due. The rule is looked up again
// rather than remembered: a session can be modified or deleted while a packet
// waits, and a pointer kept across that wait is a pointer to a rule that may
// be gone.
//------------------------------------------------------------------------------
int64_t pfcp_switch::release_shaped() {
  if (!shaping_) return -1;
  auto& sq = shaper();
  if (sq.heap.empty()) return -1;

  const uint64_t now =
      (uint64_t) std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count();
  int sent = 0;
  while (!sq.heap.empty() && sq.heap.front().due <= now) {
    const shaped_packet p = sq.heap.front();
    std::pop_heap(sq.heap.begin(), sq.heap.end(), shaped_later());
    sq.heap.pop_back();
    if (now - p.due > sq.late_max.load(std::memory_order_relaxed))
      sq.late_max.store(now - p.due, std::memory_order_relaxed);
    if (p.teid)
      pfcp_session_look_up_pack_in_access(
          (struct iphdr*) sq.payload(p.slot), p.len, p.peer, p.teid, true);
    else
      pfcp_session_look_up_pack_in_core(sq.payload(p.slot), p.len, true);
    sq.free_slots.push_back(p.slot);
    sent++;
  }
  // Send them now rather than leaving them in the batch: the packets that end
  // a burst have nothing behind them to flush it. Downlink only -- the uplink
  // writes each packet to tun as it goes.
  if (sent && upf_n3_inst) upf_n3_inst->flush_tx_batch();
  sq.queued.store(sq.heap.size(), std::memory_order_relaxed);
  if (sq.heap.empty()) return -1;
  return (int64_t) (sq.heap.front().due - now);
}

//------------------------------------------------------------------------------
// log_tun_queue_balance -- one line every LOG_PERIOD, from the first DL thread
// only. The flow hash spreads flows, not packets, so a handful of test flows
// can land unevenly; without this the symptom (one thread at 100%, the rest
// idle) is indistinguishable from a genuine ceiling.
//------------------------------------------------------------------------------
void pfcp_switch::log_tun_queue_balance() {
  std::string s;
  for (size_t i = 0; i < tun_fds_.size() && i < TUN_MAX_QUEUES; i++)
    s.append(fmt::format(
        "{}q{}: rx {} tx {}", i ? ", " : "", i,
        tun_q_[i].rx.load(std::memory_order_relaxed),
        tun_q_[i].tx.load(std::memory_order_relaxed)));
  // What the shaper is doing, if it is doing anything: how many packets it has
  // held, how many it gave up on, what it is holding now and how late it has
  // been. A shaper with no view of its own latency is how bufferbloat ships.
  uint64_t shaped = shaper_gone_held.load(std::memory_order_relaxed);
  uint64_t sdrop  = shaper_gone_dropped.load(std::memory_order_relaxed);
  uint64_t queued = 0;
  uint64_t wait   = shaper_gone_late.load(std::memory_order_relaxed);
  {
    std::lock_guard<std::mutex> lk(shaper_reg_mu);
    for (const auto* sq : shaper_reg) {
      shaped += sq->held.load(std::memory_order_relaxed);
      sdrop += sq->dropped.load(std::memory_order_relaxed);
      queued += sq->queued.load(std::memory_order_relaxed);
      const uint64_t w = sq->late_max.load(std::memory_order_relaxed);
      if (w > wait) wait = w;
    }
  }
  if (shaped || sdrop)
    s.append(fmt::format(
        "; shaper held {} dropped {} queued {} late {}us", shaped, sdrop,
        queued, wait / 1000));
  // Map versions retired but not yet freed. Non-zero is normal -- that is the
  // reclamation delay RCU trades for a lock-free read side. A peak that only
  // ever climbs is a reader that stopped leaving its critical section, which
  // from the outside is indistinguishable from a leak.
  const size_t pending = rcu_.pending();
  if (pending > rcu_pending_hwm_) rcu_pending_hwm_ = pending;
  Logger::pfcp_switch().debug(
      "tun queue balance -- %s; rcu retired %zu, peak %zu", s.c_str(), pending,
      rcu_pending_hwm_);
}

//------------------------------------------------------------------------------
// flow_hash -- stable hash of an IPv4 flow, symmetric in the two endpoints so
// both directions of a connection land on the same queue.
//------------------------------------------------------------------------------
static inline uint32_t flow_hash(const struct iphdr* iph, std::size_t len) {
  uint32_t h       = iph->saddr ^ iph->daddr;  // symmetric in addresses
  const size_t ihl = (size_t) iph->ihl * 4;
  uint16_t sport = 0, dport = 0;
  if ((iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) &&
      len >= ihl + 4) {
    memcpy(&sport, (const uint8_t*) iph + ihl, sizeof(sport));
    memcpy(&dport, (const uint8_t*) iph + ihl + 2, sizeof(dport));
  }
  h ^= (uint32_t) (uint16_t) (sport ^ dport) << 16;  // symmetric in ports
  h ^= (uint32_t) iph->protocol;
  // Finaliser: the inputs are low-entropy (one subnet, sequential UE
  // addresses), so without mixing the low bits the modulo below would leave
  // whole queues empty.
  h ^= h >> 16;
  h *= 0x7feb352dU;
  h ^= h >> 15;
  h *= 0x846ca68bU;
  h ^= h >> 16;
  return h;
}

//------------------------------------------------------------------------------
int pfcp_switch::tun_tx_fd(const struct iphdr* iph, std::size_t len) const {
  const size_t n = tun_fds_.size();
  if (n == 0) return sock_w;
  if (n == 1) return tun_fds_[0];
  return tun_fds_[flow_hash(iph, len) % n];
}

//------------------------------------------------------------------------------
void pfcp_switch::send_to_core(char* const ip_packet, const ssize_t len) {
  const struct iphdr* iph = (const struct iphdr*) ip_packet;
  const int fd            = tun_tx_fd(iph, (std::size_t) len);
  for (size_t i = 0; i < tun_fds_.size() && i < TUN_MAX_QUEUES; i++)
    if (tun_fds_[i] == fd) {
      tun_q_[i].tx.fetch_add(1, std::memory_order_relaxed);
      break;
    }

  // The queue was opened with IFF_VNET_HDR, so every write has to start with
  // one. These packets arrive one at a time off the air and are already at
  // most an MTU, so there is nothing to coalesce: the header says "no GSO, no
  // checksum work" and the payload follows unchanged. writev keeps that a
  // single syscall rather than prepending the header with a copy.
  struct upf_vnet_hdr vnet = {};
  vnet.flags               = 0;
  vnet.gso_type            = UPF_VNET_HDR_GSO_NONE;
  struct iovec iov[2];
  iov[0].iov_base = &vnet;
  iov[0].iov_len  = sizeof(vnet);
  iov[1].iov_base = ip_packet;
  iov[1].iov_len  = (size_t) len;

  // The fd is non-blocking so the downlink reader does not need a poll() per
  // packet. EAGAIN here means the queue is momentarily full, not that the
  // packet should be dropped -- wait briefly rather than lose it.
  for (int attempt = 0;; attempt++) {
    const ssize_t w = writev(fd, iov, 2);
    if (w >= 0) return;
    if (errno == EINTR) continue;
    if ((errno == EAGAIN || errno == EWOULDBLOCK) && attempt < 8) {
      struct pollfd p = {fd, POLLOUT, 0};
      poll(&p, 1, 1);
      continue;
    }
    Logger::pfcp_switch().error(
        "write fd %d failed rc=%d:%s", fd, w, strerror(errno));
    return;
  }
}

// =============================================================================
// PDN socket / tun helpers
// =============================================================================

//------------------------------------------------------------------------------
int pfcp_switch::create_pdn_socket(
    const char* const ifname, const bool promisc, int& if_index) {
  struct sockaddr_in addr = {};
  int sd                  = 0;

  /*
   * Create socket
   * The  socket_type is either SOCK_RAW for raw packets including the
   * link-level header or SOCK_DGRAM for cooked packets with the link-level
   * header removed.
   */

  if ((sd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL))) < 0) {
    /*
     * Socket creation has failed...
     */
    Logger::pfcp_switch().error("Socket creation failed (%s)", strerror(errno));
    return RETURNerror;
  }

  if (ifname) {
    struct ifreq ifr = {};
    strncpy((char*) ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(sd, SIOCGIFINDEX, &ifr) < 0) {
      Logger::pfcp_switch().error(
          "Get interface index failed (%s) for %s", strerror(errno), ifname);
      close(sd);
      return RETURNerror;
    }

    if_index = ifr.ifr_ifindex;

    struct sockaddr_ll sll = {};
    sll.sll_family         = AF_PACKET;        /* Always AF_PACKET */
    sll.sll_protocol       = htons(ETH_P_ALL); /* Physical-layer protocol */
    sll.sll_ifindex        = ifr.ifr_ifindex;  /* Interface number */
    sll.sll_pkttype        = PACKET_HOST;
    if (bind(sd, (struct sockaddr*) &sll, sizeof(sll)) < 0) {
      /*
       * Bind failed
       */
      Logger::pfcp_switch().error(
          "Socket bind to %s failed (%s)", ifname, strerror(errno));
      close(sd);
      return RETURNerror;
    }

    if (promisc) {
      struct packet_mreq mreq = {};
      mreq.mr_ifindex         = if_index;
      mreq.mr_type            = PACKET_MR_PROMISC;
      if (setsockopt(
              sd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        Logger::pfcp_switch().error(
            "Set promiscuous mode failed (%s)", strerror(errno));
        close(sd);
        return RETURNerror;
      }
    }
  }
  return sd;
}

//------------------------------------------------------------------------------
int pfcp_switch::create_pdn_socket(const char* const ifname) {
  struct sockaddr_in addr = {};
  int sd                  = RETURNerror;

  if (ifname) {
    /*
     * Create socket
     * The  socket_type is either SOCK_RAW for raw packets including the
     * link-level header or SOCK_DGRAM for cooked packets with the link-level
     * header removed.
     */
    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
      /*
       * Socket creation has failed...
       */
      Logger::pfcp_switch().error(
          "Socket creation failed (%s)", strerror(errno));
      return RETURNerror;
    }

    int option_on          = 1;
    const int* p_option_on = &option_on;
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, p_option_on, sizeof(option_on)) <
        0) {
      Logger::pfcp_switch().error(
          "Set header included failed (%s)", strerror(errno));
      close(sd);
      return RETURNerror;
    }

    struct ifreq ifr = {};
    strncpy((char*) ifr.ifr_name, ifname, IFNAMSIZ);
    if ((setsockopt(
            sd, SOL_SOCKET, SO_BINDTODEVICE, (void*) &ifr, sizeof(ifr))) < 0) {
      Logger::pfcp_switch().error(
          "Socket bind to %s failed (%s)", ifname, strerror(errno));
      close(sd);
      return RETURNerror;
    }
    return sd;
  }
  return RETURNerror;
}

//------------------------------------------------------------------------------
int pfcp_switch::tun_open(char* devname, int flags, bool multi_queue) {
  struct ifreq ifr;
  int fd, err;
  if ((fd = open("/dev/net/tun", flags)) == -1) {
    Logger::pfcp_switch().error("open /dev/net/tun");
    return RETURNerror;
  }
  memset(&ifr, 0, sizeof(ifr));
  // IFF_VNET_HDR is what makes a tun fd able to carry more than one packet per
  // syscall. Without it the kernel segments every TCP stream down to the MTU
  // before handing it over, so a 3 Gbit/s flow costs ~270k read() calls a
  // second and each one allocates an skb and copies ~1.4 kB -- which is where
  // essentially all of the CPU went (97% kernel time, most of it in
  // tun_get_user). With it, each packet is prefixed by a virtio_net_hdr and
  // the kernel may hand over a single segment of up to 64 kB, which this code
  // then splits itself. One syscall for ~45 packets instead of 45.
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_VNET_HDR;
  // Each open with IFF_MULTI_QUEUE attaches another queue to the same device.
  // The device itself must have been created with multi_queue or this fails.
  if (multi_queue) ifr.ifr_flags |= IFF_MULTI_QUEUE;
  strncpy(ifr.ifr_name, devname, IFNAMSIZ);  // devname = tunX

  if ((err = ioctl(fd, TUNSETIFF, (void*) &ifr)) == -1) {
    Logger::pfcp_switch().error("ioctl TUNSETIFF %d %s", err, strerror(errno));
    close(fd);
    return RETURNerror;
  }

  // The header size has to be agreed explicitly: the kernel defaults to the
  // 10-byte layout but will use 12 if asked, and reading the wrong number of
  // bytes shifts every packet.
  int vnet_hdr_sz = (int) sizeof(struct upf_vnet_hdr);
  if (ioctl(fd, TUNSETVNETHDRSZ, &vnet_hdr_sz) == -1) {
    Logger::pfcp_switch().error(
        "ioctl TUNSETVNETHDRSZ %s -- falling back to one packet per syscall",
        strerror(errno));
    close(fd);
    return RETURNerror;
  }

  // Announce what this code can un-do itself. TSO is the one that matters:
  // it is what lets the kernel stop segmenting. Checksum offload comes with
  // it, because a segment the kernel has not split has no per-segment
  // checksum to compute -- segment_and_forward() computes them.
  const unsigned int offload =
      TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_TSO_ECN;
  if (ioctl(fd, TUNSETOFFLOAD, offload) == -1) {
    // Not fatal: without it the kernel simply keeps segmenting for us, which
    // is exactly the old behaviour. The vnet header is still present.
    Logger::pfcp_switch().warn(
        "ioctl TUNSETOFFLOAD %s -- kernel will keep segmenting, expect the "
        "old one-syscall-per-packet cost",
        strerror(errno));
  }
  return fd;
}

//------------------------------------------------------------------------------
void pfcp_switch::setup_pdn_interfaces() {
  std::string cmd = {};
  int rc          = 0;
  // Needed before the device exists: multi_queue can only be asked for at
  // creation time, so the thread count has to be known here.
  int nt = upf_cfg.dl_rx_queues < 1 ? 1 : upf_cfg.dl_rx_queues;
  if (nt > TUN_MAX_QUEUES) nt = TUN_MAX_QUEUES;
  int if_index = 0;

  for (int index = 0; index < upf_cfg.pdns.size(); index++) {
    pdn_cfg_t it = upf_cfg.pdns[index];
    int sock_r   = 0;
    if (index == 0) {
      cmd = fmt::format(
          "ip tuntap add mode tun {}dev tun{}", nt > 1 ? "multi_queue " : "",
          index);
      rc = system((const char*) cmd.c_str());

      cmd = fmt::format("ip link set dev tun{} up", index);
      rc  = system((const char*) cmd.c_str());

      cmd = fmt::format("ethtool -K tun{0} tx-checksum-ip-generic off;", index);
      rc  = system((const char*) cmd.c_str());
    }
    if (it.prefix_ipv4) {
      struct in_addr address4 = {};
      address4.s_addr         = it.network_ipv4.s_addr + be32toh(1);

      if (index == 0) {
        cmd = fmt::format(
            "ip addr add {}/{} dev tun{}",
            oai::utils::conv::toString(address4).c_str(), it.prefix_ipv4,
            index);
        rc = system((const char*) cmd.c_str());
      } else {
        // Remove defult route
        // cmd = fmt::format(
        //     "ip route del {}/{}",
        //     oai::utils::conv::toString(it.network_ipv4).c_str(),
        //     it.prefix_ipv4);
        // rc = system((const char*) cmd.c_str());

        // Add first pdn as gateway for additional PDNs
        struct in_addr address4_gw = {};
        address4_gw.s_addr = upf_cfg.pdns[0].network_ipv4.s_addr + be32toh(1);

        auto routing_info = fr::RoutingInformation{
            oai::utils::conv::toString(it.network_ipv4),
            static_cast<uint32_t>(it.prefix_ipv4), "tun0",
            oai::utils::conv::toString(address4_gw)};
        local_routing->add_route(routing_info);
      }

      if (upf_cfg.enable_snat) {
        auto snat_info = fr::SourceNatInformation{
            oai::utils::conv::toString(it.network_ipv4),
            static_cast<uint32_t>(it.prefix_ipv4), upf_cfg.n6.if_name,
            oai::utils::conv::toString(upf_cfg.n6.addr4)};
        local_routing->add_source_snat(snat_info);
      }
    }
    if (it.prefix_ipv6) {
      std::string cmd = fmt::format(
          "echo 0 > /proc/sys/net/ipv6/conf/tun{}/disable_ipv6", index);
      rc = system((const char*) cmd.c_str());

      struct in6_addr addr6 = it.network_ipv6;
      addr6.s6_addr[15]     = 1;
      cmd                   = fmt::format(
          "ip -6 addr add {}/{} dev tun{}",
          oai::utils::conv::toString(addr6).c_str(), it.prefix_ipv6, index);
      rc = system((const char*) cmd.c_str());
      // if ((it.enable_snat) && (/* SGI has IPv6 address*/)) {
      //   cmd = fmt::format(
      //       "ip6tables -t nat -A POSTROUTING -s {}/{} -o {} -j
      //       SNAT-- to -
      //       source {} ", oai::utils::conv::toString(addr6).c_str(),
      //       it.prefix_ipv6, xxx);
      //   rc = system((const char*) cmd.c_str());
      // }
    }
    // even if we do nat, we can receive ue ip destinated IP packet
    // but do not forget to set routes outside UPF
    // cmd = fmt::format(
    //    "/sbin/sysctl -w net.ipv4.conf.{}.rp_filter=0",
    //    upf_cfg.n6.if_name.c_str());
    // rc = system((const char*) cmd.c_str());

    // Otherwise redirect incoming ingress UE IP to default gw
    // cmd = fmt::format("/sbin/sysctl -w net.ipv4.conf.tun{}.send_redirects=0",
    // index); rc = system ((const char*)cmd.c_str()); cmd =
    // fmt::format("/sbin/sysctl -w net.ipv4.conf.tun{}.accept_redirects=0",
    // index); rc = system ((const char*)cmd.c_str());

    if (index == 0) {
      // One queue per thread. The kernel hashes each packet's flow and always
      // puts a given flow in the same queue, so the thread that owns it is the
      // only one that ever sees that flow -- ordering costs nothing and the
      // threads no longer contend on one queue's lock. O_NONBLOCK lets the
      // reader drain with one syscall per packet instead of poll()+read().
      cmd = fmt::format("tun{}", index);
      for (int q = 0; q < nt; q++) {
        const int fd =
            tun_open((char*) cmd.c_str(), O_RDWR | O_NONBLOCK, nt > 1);
        if (fd == RETURNerror) {
          Logger::pfcp_switch().error(
              "Could not open tun%d queue %d of %d", index, q, nt);
          sleep(2);
          exit(EXIT_FAILURE);
        }
        tun_fds_.push_back(fd);
      }
      sock_r = tun_fds_[0];
      sock_w = tun_fds_[0];

      const std::vector<int> cpus =
          nt > 1 ? udp_server::datapath_cpus(nt) : std::vector<int>{};
      std::string where;
      for (int c : cpus)
        where.append(where.empty() ? " on CPU " : ",")
            .append(std::to_string(c));
      Logger::pfcp_switch().info(
          "tun%d: %d receive thread(s), one queue each%s", index, nt,
          where.c_str());
      for (int q = 0; q < nt; q++) {
        oai::utils::thread_sched_params sp = upf_cfg.n6.thread_rd_sched_params;
        if (!cpus.empty()) sp.cpu_id = cpus[q];
        prThreads_.emplace_back(
            &pfcp_switch::pdn_read_loop, this, tun_fds_[q], q, sp);
      }
      socks_r_ptr[index] = sock_r;
    }
  }

  // Disable filtering for cluster deployement
  // rc = system("/sbin/sysctl -w net.ipv4.conf.all.forwarding=1");
  // rc = system("/sbin/sysctl -w net.ipv4.conf.all.send_redirects=0");
  // rc = system("/sbin/sysctl -w net.ipv4.conf.default.send_redirects=0");
  // rc = system("/sbin/sysctl -w net.ipv4.conf.all.accept_redirects=0");
  // rc = system("/sbin/sysctl -w net.ipv4.conf.default.accept_redirects=0");
}

// =============================================================================
// Constructor / destructor
// =============================================================================

//------------------------------------------------------------------------------
// generate_fteid_n3 — allocate a new local N3 F-TEID (§8.2.3, V17.10.0).
//------------------------------------------------------------------------------
pfcp::fteid_t pfcp_switch::generate_fteid_n3() {
  pfcp::fteid_t fteid = {};
  fteid.teid          = generate_teid_n3();
  if (upf_cfg.n3.addr4.s_addr) {
    fteid.v4                  = 1;
    fteid.ipv4_address.s_addr = upf_cfg.n3.addr4.s_addr;
  } else {
    fteid.v6           = 1;
    fteid.ipv6_address = upf_cfg.n3.addr6;
  }
  return fteid;
}

//------------------------------------------------------------------------------
pfcp_switch::pfcp_switch()
    : seid_generator_(),
      teid_n3_generator__(),
      up_seid2pfcp_sessions(PFCP_SWITCH_MAX_SESSIONS, rcu_),
      ul_n3_teid2pfcp_pdr(PFCP_SWITCH_MAX_PDRS, rcu_),
      ue_ipv4_hbo2pfcp_pdr(PFCP_SWITCH_MAX_PDRS, rcu_),
      sock_w(0) {
  bool isBpfAccelerationEnabled = upf_cfg.enable_bpf_datapath;
  socks_r_ptr                   = {};
  prThreadToCancel              = (pthread_t) 0;

  if (!isBpfAccelerationEnabled) {
    timer_min_commit_interval_id = 0;
    timer_max_commit_interval_id = 0;
    cp_fseid2pfcp_sessions = {}, sock_w = -1;
    pdn_if_index = -1;
    setup_pdn_interfaces();

    // Usage reporting for the simple switch. The BPF datapath measures in
    // urr_config_map and reports from its own path, so this thread is only
    // started here.
    if (upf_cfg.enable_urr) {
      thread_usage_report_ = std::thread(&pfcp_switch::usage_report_loop, this);
    }
  }
}

//------------------------------------------------------------------------------
pfcp_switch::~pfcp_switch() {
  int res;

  for (int index = 0; index < upf_cfg.pdns.size(); index++) {
    shutdown(socks_r_ptr[index], SHUT_RDWR);
  }
  for (auto& t : prThreads_) {
    if (t.joinable()) {
      res = pthread_cancel(t.native_handle());
      if (res != 0) {
        Logger::pfcp_switch().error("could not cancel pdn_read thread");
      }
    }
  }
  for (auto& t : prThreads_) {
    if (t.joinable()) t.join();
  }
  usage_report_stop_.store(true, std::memory_order_relaxed);
  if (thread_usage_report_.joinable()) thread_usage_report_.join();
  for (int fd : tun_fds_) close(fd);
}

// =============================================================================
// Session / PDR hash-table helpers
// =============================================================================

//------------------------------------------------------------------------------
bool pfcp_switch::get_pfcp_session_by_cp_fseid(
    const pfcp::fseid_t& fseid,
    std::shared_ptr<pfcp::pfcp_session>& session) const {
  std::unordered_map<
      fseid_t, std::shared_ptr<pfcp::pfcp_session>>::const_iterator sit =
      cp_fseid2pfcp_sessions.find(fseid);
  if (sit == cp_fseid2pfcp_sessions.end()) return false;
  session = sit->second;
  return true;
}

//------------------------------------------------------------------------------
bool pfcp_switch::get_pfcp_session_by_up_seid(
    const uint64_t cp_seid,
    std::shared_ptr<pfcp::pfcp_session>& session) const {
  oai::upf::rcu_guard g(rcu_);
  const auto* v = up_seid2pfcp_sessions.find(cp_seid);
  if (!v) return false;
  session = *v;  // control-plane caller wants ownership
  return true;
}

//------------------------------------------------------------------------------
bool pfcp_switch::get_pfcp_ul_pdrs_by_up_teid(
    const teid_t teid,
    std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>& pdrs) const {
  oai::upf::rcu_guard g(rcu_);
  const auto* v = ul_n3_teid2pfcp_pdr.find(teid);
  if (!v) return false;
  pdrs = *v;
  return true;
}

//------------------------------------------------------------------------------
bool pfcp_switch::get_pfcp_dl_pdrs_by_ue_ip(
    const uint32_t ue_ip,
    std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>& pdrs) const {
  oai::upf::rcu_guard g(rcu_);
  const auto* v = ue_ipv4_hbo2pfcp_pdr.find(ue_ip);
  if (!v) return false;
  pdrs = *v;
  return true;
}

//------------------------------------------------------------------------------
void pfcp_switch::add_pfcp_session_by_cp_fseid(
    const pfcp::fseid_t& fseid, std::shared_ptr<pfcp::pfcp_session>& session) {
  std::pair<fseid_t, std::shared_ptr<pfcp::pfcp_session>> entry(fseid, session);
  cp_fseid2pfcp_sessions.insert(entry);
}

//------------------------------------------------------------------------------
// send_usage_report -- 3GPP TS 29.244 §7.5.8, Usage Report within a Session
// Report Request.
//
// Reports the volume accumulated since the previous report, not a running
// total: the SMF sums the deltas, and a delta stays correct across a restart
// of either end in a way a cumulative counter does not.
//------------------------------------------------------------------------------
bool pfcp_switch::send_usage_report(
    std::shared_ptr<pfcp::pfcp_session>& session, bool periodic) {
  if (!session) return false;

  // The periodic thread and session teardown can both land here for the same
  // session. Reading the counters, moving the watermark and taking a sequence
  // number have to happen as one step, or two reports overlap and the SMF
  // either double-counts a delta or never sees one.
  std::lock_guard<std::mutex> lk(session->report_mutex);

  const uint64_t ul  = session->total_ul_octets();
  const uint64_t dl  = session->total_dl_octets();
  const uint64_t ulp = session->total_ul_packets();
  const uint64_t dlp = session->total_dl_packets();

  const uint64_t d_ul  = ul - session->reported_ul_octets;
  const uint64_t d_dl  = dl - session->reported_dl_octets;
  const uint64_t d_ulp = ulp - session->reported_ul_packets;
  const uint64_t d_dlp = dlp - session->reported_dl_packets;

  // Nothing moved: a report saying zero tells the SMF nothing it cannot
  // already assume, and one per session per period would be pure noise.
  if (d_ul == 0 && d_dl == 0) return false;

  pfcp::pfcp_session_report_request h;

  pfcp::report_type_t report = {};
  report.usar                = 1;  // Usage Report -- §8.2.21
  h.set(report);

  pfcp::usage_report_within_pfcp_session_report_request ur = {};

  // One URR per session is what the SMF creates here; if it sent several we
  // still have a single set of counters, so report against the first.
  pfcp::urr_id_t urr_id = {};
  if (!session->urrs.empty() && session->urrs[0] &&
      session->urrs[0]->urr_id.first) {
    urr_id = session->urrs[0]->urr_id.second;
  }
  ur.set(urr_id);

  pfcp::ur_seqn_t seqn = {};
  seqn.ur_seqn         = session->ur_seqn++;
  ur.set(seqn);

  pfcp::usage_report_trigger_t trigger = {};
  if (periodic) {
    trigger.perio = 1;  // periodic reporting
  } else {
    trigger.immer = 1;  // immediate report (session teardown / query)
  }
  ur.set(trigger);

  pfcp::volume_measurement_t vol = {};
  vol.tovol                      = 1;
  vol.ulvol                      = 1;
  vol.dlvol                      = 1;
  vol.tonop                      = 1;
  vol.ulnop                      = 1;
  vol.dlnop                      = 1;
  vol.total_volume               = d_ul + d_dl;
  vol.uplink_volume              = d_ul;
  vol.downlink_volume            = d_dl;
  vol.total_nop                  = d_ulp + d_dlp;
  vol.uplink_nop                 = d_ulp;
  vol.downlink_nop               = d_dlp;
  ur.set(vol);

  pfcp::duration_measurement_t dur = {};
  dur.duration =
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::steady_clock::now() - session->measurement_start)
          .count();
  ur.set(dur);

  h.set(ur);

  // Advance the watermark only once the message is handed to N4. The counters
  // keep climbing underneath; taking the delta against the values read at the
  // top means traffic during this call is counted next time, never dropped.
  session->reported_ul_octets  = ul;
  session->reported_dl_octets  = dl;
  session->reported_ul_packets = ulp;
  session->reported_dl_packets = dlp;

  upf_n4_inst->send_n4_msg(session->cp_fseid, h);

  Logger::pfcp_switch().debug(
      "Usage Report seid 0x%lx: ul=%lu B (%lu pkt) dl=%lu B (%lu pkt)",
      session->seid, d_ul, d_ulp, d_dl, d_dlp);
  return true;
}

//------------------------------------------------------------------------------
// usage_report_loop -- one thread for every session, not one per session.
//
// Reporting is a control-plane rate: a handful of messages per session per
// minute. A thread each would cost more in stacks and scheduler pressure than
// the reports are worth, so this walks the session table on a fixed tick.
//------------------------------------------------------------------------------
void pfcp_switch::usage_report_loop() {
  // §8.2.42 Measurement Period is per URR; the SMF in this deployment does not
  // send one, so fall back to a period that is frequent enough to be useful
  // and rare enough to be invisible.
  constexpr int kPeriodSeconds = 30;

  while (!usage_report_stop_.load(std::memory_order_relaxed)) {
    // One-second ticks, so shutdown does not wait out a whole period.
    for (int i = 0; i < kPeriodSeconds; i++) {
      std::this_thread::sleep_for(std::chrono::seconds(1));
      if (usage_report_stop_.load(std::memory_order_relaxed)) return;
    }
    if (!upf_cfg.enable_urr) continue;

    std::vector<std::shared_ptr<pfcp::pfcp_session>> snapshot;
    up_seid2pfcp_sessions.for_each(
        [&snapshot](
            const uint64_t&, const std::shared_ptr<pfcp::pfcp_session>& v) {
          if (v) snapshot.push_back(v);
        });
    for (auto& sess : snapshot) send_usage_report(sess, true);
  }
}

//------------------------------------------------------------------------------
// resolve_pdr_qfis -- which QFI each PDR's packets must carry, worked out
// once per session change.
//
// An uplink PDR has it in its PDI. A downlink PDR does not: every downlink
// FAR of a session shares one TEID, so the QoS flows are told apart solely by
// the QFI in the PDU Session Container, which comes from the linked QER.
//------------------------------------------------------------------------------
void pfcp_switch::resolve_pdr_qfis(
    std::shared_ptr<pfcp::pfcp_session>& session) {
  if (!session) return;
  for (const auto& p : session->pdrs) {
    if (!p) continue;
    if (p->pdi.first && p->pdi.second.qfi.first) {
      p->tx_qfi = p->pdi.second.qfi.second.qfi;
      continue;
    }
    p->tx_qfi = -1;
    if (!p->qer_id.first) continue;
    std::shared_ptr<pfcp::pfcp_qer> q = {};
    if (session->get(p->qer_id.second.qer_id, q) && q && q->qos_flow_id.first)
      p->tx_qfi = q->qos_flow_id.second.qfi;
  }
}

//------------------------------------------------------------------------------
// apply_qos_mbr -- give every PDR the meter its QoS flow is entitled to.
//
// A QER carries the MBR (3GPP TS 29.244 §8.2.8). Which QER bounds the whole
// session and which bounds one flow is not flagged anywhere: the session-AMBR
// QER is the one every QoS flow's PDRs point at, a per-flow QER is pointed at
// by a single flow's. So classify by how many distinct QFIs reference each,
// which is structural rather than a guess from the rates.
//------------------------------------------------------------------------------
void pfcp_switch::apply_qos_mbr(std::shared_ptr<pfcp::pfcp_session>& session) {
  if (!upf_cfg.enable_qos || upf_cfg.enable_bpf_datapath || !session) return;

  std::unordered_map<uint32_t, std::shared_ptr<pfcp::pfcp_qer>> qer_by_id;
  for (const auto& q : session->qers)
    if (q && q->qer_id.first) qer_by_id[q->qer_id.second.qer_id] = q;

  // A QFI is 6 bits (§8.2.89), so the QFIs pointing at a QER fit in a mask.
  std::unordered_map<uint32_t, uint64_t> qfis_of;
  for (const auto& p : session->pdrs)
    if (p && p->qer_id.first)
      qfis_of[p->qer_id.second.qer_id] |=
          1ULL << (p->tx_qfi < 0 ? 0 : p->tx_qfi & 63);

  const auto session_wide = [&qfis_of](uint32_t id) {
    const auto it = qfis_of.find(id);
    // Referenced by no PDR at all: an AMBR QER the SMF sent without wiring it
    // to one, which is how several of them signal the session limit.
    // More than one bit set: shared by several flows, so session-wide.
    return it == qfis_of.end() || (it->second & (it->second - 1)) != 0;
  };

  // PFCP expresses MBR in kbit/s (§8.2.8).
  uint64_t sess_ul = 0, sess_dl = 0;
  for (const auto& e : qer_by_id) {
    if (!e.second->maximum_bitrate.first || !session_wide(e.first)) continue;
    const uint64_t ul = e.second->maximum_bitrate.second.ul_mbr * 1000ULL;
    const uint64_t dl = e.second->maximum_bitrate.second.dl_mbr * 1000ULL;
    if (ul && (!sess_ul || ul < sess_ul)) sess_ul = ul;
    if (dl && (!sess_dl || dl < sess_dl)) sess_dl = dl;
  }

  // One AMBR bucket per direction for the whole session, kept on the session
  // and handed to every PDR of that direction -- the AMBR is a limit on the
  // session, so its credit has to be spent from one place. Rebuilt only when
  // the rate changes, so a Session Modification does not reset the credit.
  // One tolerance, read two ways: where the direction shapes it is how long a
  // packet may wait for its slot, otherwise it is the burst a policer forgives.
  // The two directions are set apart because they are not the same problem --
  // see qos_shape_ul_ms.
  const bool shape_dl = upf_cfg.qos_shape_ms > 0;
  const bool shape_ul = upf_cfg.qos_shape_ul_ms > 0;
  const uint64_t tol_dl =
      shape_dl ? upf_cfg.qos_shape_ms : upf_cfg.qos_burst_ms;
  const uint64_t tol_ul =
      shape_ul ? upf_cfg.qos_shape_ul_ms : upf_cfg.qos_burst_ms;
  const auto session_bucket = [](std::shared_ptr<oai::upf::qos_bucket>& b,
                                 uint64_t bps, uint64_t tol, bool shape) {
    if (!bps)
      b.reset();
    else if (!b || b->rate() != bps)
      b = std::make_shared<oai::upf::qos_bucket>(bps, tol, shape);
  };
  session_bucket(session->qos_session_ul, sess_ul, tol_ul, shape_ul);
  session_bucket(session->qos_session_dl, sess_dl, tol_dl, shape_dl);

  for (const auto& p : session->pdrs) {
    if (!p || !p->pdi.first) continue;
    const bool is_dl = p->pdi.second.source_interface.first &&
                       p->pdi.second.source_interface.second.interface_value ==
                           INTERFACE_VALUE_CORE;
    uint64_t flow = 0;
    if (p->qer_id.first) {
      const auto it = qer_by_id.find(p->qer_id.second.qer_id);
      if (it != qer_by_id.end() && it->second->maximum_bitrate.first &&
          !session_wide(it->first))
        flow = is_dl ? it->second->maximum_bitrate.second.dl_mbr * 1000ULL :
                       it->second->maximum_bitrate.second.ul_mbr * 1000ULL;
    }
    const auto& sess =
        is_dl ? session->qos_session_dl : session->qos_session_ul;

    // Published rather than assigned. Every datapath thread reads this
    // pointer once per packet while this runs on the N4 thread, and a plain
    // shared_ptr write racing a read is undefined: the pointer and its
    // control block do not move together, so a reader can see one without
    // the other and drop the last reference to a meter still in use. A mutex
    // would also be correct, at the price of a lock on the per-packet path to
    // serialise against a writer that runs once per session modification.
    const auto cur =
        std::atomic_load_explicit(&p->qos, std::memory_order_acquire);
    if (!flow && !sess) {
      if (cur)
        std::atomic_store_explicit(
            &p->qos, std::shared_ptr<oai::upf::qos_mbr>(),
            std::memory_order_release);
    } else if (!cur || !cur->same_as(flow, sess)) {
      std::atomic_store_explicit(
          &p->qos,
          std::make_shared<oai::upf::qos_mbr>(
              flow, sess, is_dl ? tol_dl : tol_ul, is_dl ? shape_dl : shape_ul),
          std::memory_order_release);
    }
    Logger::pfcp_switch().debug(
        "QoS/MBR: seid 0x%lx PDR %u %s: flow %lu bps, session %lu bps",
        session->seid, p->pdr_id.rule_id, is_dl ? "downlink" : "uplink", flow,
        sess ? sess->rate() : 0);
  }
}

//------------------------------------------------------------------------------
void pfcp_switch::add_pfcp_session_by_up_seid(
    const uint64_t seid, std::shared_ptr<pfcp::pfcp_session>& session) {
  insert_or_error(up_seid2pfcp_sessions, seid, session, "session");
}

//------------------------------------------------------------------------------
void pfcp_switch::remove_pfcp_session(
    std::shared_ptr<pfcp::pfcp_session>& session) {
  // Last chance to account for this session: whatever it moved since the
  // previous periodic report would otherwise be lost with it.
  if (upf_cfg.enable_urr && !upf_cfg.enable_bpf_datapath) {
    send_usage_report(session, false);
  }
  session->cleanup();
  cp_fseid2pfcp_sessions.erase(session->cp_fseid);
  up_seid2pfcp_sessions.erase(session->seid);
}

//------------------------------------------------------------------------------
void pfcp_switch::remove_pfcp_session(const pfcp::fseid_t& cp_fseid) {
  std::shared_ptr<pfcp::pfcp_session> session = {};
  if (get_pfcp_session_by_cp_fseid(cp_fseid, session)) {
    remove_pfcp_session(session);
  }
}

//------------------------------------------------------------------------------
// add_pfcp_ul_pdr_by_up_teid — insert PDR into sorted-by-precedence vector.
// Creates the entry if the TEID is new; inserts in-order if TEID already
// exists.

//------------------------------------------------------------------------------
void pfcp_switch::add_pfcp_ul_pdr_by_up_teid(
    const teid_t teid, std::shared_ptr<pfcp::pfcp_pdr>& pdr) {
  // Copy-on-write. The old code push_back()ed into the live vector while
  // datapath threads were iterating it -- a race that no amount of reference
  // counting fixed, because the shared_ptr protected the vector object, not
  // its contents. Building a new vector and publishing it means a reader
  // always sees one immutable, internally consistent list; the old one is
  // freed by the RCU domain once those readers have finished with it.
  auto fresh = std::make_shared<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>();
  {
    oai::upf::rcu_guard g(rcu_);
    const auto* cur = ul_n3_teid2pfcp_pdr.find(teid);
    if (cur) *fresh = **cur;  // copy the existing entries
  }
  // Ordered by precedence, lowest value first: §8.2.11 makes the lower value
  // the higher precedence, and the look-up takes the first PDR that matches.
  // Drop an older copy of this same PDR first, so a repeated Session
  // Modification does not stack duplicates behind each other.
  fresh->erase(
      std::remove_if(
          fresh->begin(), fresh->end(),
          [&pdr](const std::shared_ptr<pfcp::pfcp_pdr>& e) {
            return e && e->local_seid == pdr->local_seid &&
                   e->pdr_id.rule_id == pdr->pdr_id.rule_id;
          }),
      fresh->end());
  auto it = fresh->begin();
  while (it != fresh->end() && *(*it) < *pdr) ++it;
  fresh->insert(it, pdr);
  insert_or_error(ul_n3_teid2pfcp_pdr, teid, fresh, "uplink PDR");
}

//------------------------------------------------------------------------------
// remove_pdr_from_lookup -- take one PDR out of the table that feeds it.
//
// A PFCP Remove PDR used to take the rule out of the session and stop there,
// so the TEID and UE-IP tables kept forwarding through it until the whole
// session was deleted. Publishing a new vector without that PDR closes the
// window without one: readers hold an rcu_guard and see either list whole.
//------------------------------------------------------------------------------
void pfcp_switch::remove_pdr_from_lookup(
    const std::shared_ptr<pfcp::pfcp_pdr>& pdr) {
  if (!pdr || !pdr->pdi.first || !pdr->pdi.second.source_interface.first)
    return;
  const auto& pdi = pdr->pdi.second;

  if (pdi.source_interface.second.interface_value == INTERFACE_VALUE_ACCESS &&
      pdi.local_fteid.first) {
    const teid_t teid = pdi.local_fteid.second.teid;
    auto fresh =
        std::make_shared<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>();
    {
      oai::upf::rcu_guard g(rcu_);
      const auto* cur = ul_n3_teid2pfcp_pdr.find(teid);
      if (cur) {
        for (const auto& p : **cur)
          if (p != pdr) fresh->push_back(p);
      }
    }
    if (fresh->empty())
      remove_pfcp_ul_pdrs_by_up_teid(teid);
    else
      insert_or_error(ul_n3_teid2pfcp_pdr, teid, fresh, "uplink PDR");

  } else if (
      pdi.source_interface.second.interface_value == INTERFACE_VALUE_CORE &&
      pdi.ue_ip_address.first && pdi.ue_ip_address.second.v4) {
    const uint32_t ue_ip =
        be32toh(pdi.ue_ip_address.second.ipv4_address.s_addr);
    auto fresh =
        std::make_shared<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>();
    {
      oai::upf::rcu_guard g(rcu_);
      const auto* cur = ue_ipv4_hbo2pfcp_pdr.find(ue_ip);
      if (cur) {
        for (const auto& p : **cur)
          if (p != pdr) fresh->push_back(p);
      }
    }
    if (fresh->empty())
      remove_pfcp_dl_pdrs_by_ue_ip(ue_ip);  // also drops any framed routes
    else
      insert_or_error(ue_ipv4_hbo2pfcp_pdr, ue_ip, fresh, "downlink PDR");
  }
}

//------------------------------------------------------------------------------
// replace_pdr_in_lookup -- point the tables at an updated PDR.
//
// The key lives in the PDI, so an Update PDR can move the rule to a different
// TEID or UE address. Under the same key one publish swaps the rule and a
// reader never sees it missing; across keys the new entry goes in first, so
// the flow stays reachable while the old one is retired.
//------------------------------------------------------------------------------
void pfcp_switch::replace_pdr_in_lookup(
    const std::shared_ptr<pfcp::pfcp_pdr>& old_pdr,
    const std::shared_ptr<pfcp::pfcp_pdr>& new_pdr) {
  if (!old_pdr || !new_pdr) return;

  const auto key_of = [](const std::shared_ptr<pfcp::pfcp_pdr>& p, bool& is_ul,
                         teid_t& teid, uint32_t& ue_ip) {
    is_ul = false;
    teid  = 0;
    ue_ip = 0;
    if (!p->pdi.first || !p->pdi.second.source_interface.first) return false;
    const auto& pdi = p->pdi.second;
    if (pdi.source_interface.second.interface_value == INTERFACE_VALUE_ACCESS &&
        pdi.local_fteid.first) {
      is_ul = true;
      teid  = pdi.local_fteid.second.teid;
      return true;
    }
    if (pdi.source_interface.second.interface_value == INTERFACE_VALUE_CORE &&
        pdi.ue_ip_address.first && pdi.ue_ip_address.second.v4) {
      ue_ip = be32toh(pdi.ue_ip_address.second.ipv4_address.s_addr);
      return true;
    }
    return false;
  };

  bool o_ul = false, n_ul = false;
  teid_t o_teid = 0, n_teid = 0;
  uint32_t o_ip = 0, n_ip = 0;
  const bool o_keyed = key_of(old_pdr, o_ul, o_teid, o_ip);
  const bool n_keyed = key_of(new_pdr, n_ul, n_teid, n_ip);

  if (!n_keyed) {  // the update left it with no key of its own
    if (o_keyed) remove_pdr_from_lookup(old_pdr);
    return;
  }

  // Same key: one copy-on-write publish with the old rule swapped out.
  if (o_keyed && o_ul == n_ul &&
      ((n_ul && o_teid == n_teid) || (!n_ul && o_ip == n_ip))) {
    auto fresh =
        std::make_shared<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>();
    {
      oai::upf::rcu_guard g(rcu_);
      const auto* cur = n_ul ? ul_n3_teid2pfcp_pdr.find(n_teid) :
                               ue_ipv4_hbo2pfcp_pdr.find(n_ip);
      if (cur) {
        for (const auto& p : **cur)
          fresh->push_back(p == old_pdr ? new_pdr : p);
      }
    }
    if (fresh->empty()) fresh->push_back(new_pdr);
    if (n_ul)
      insert_or_error(ul_n3_teid2pfcp_pdr, n_teid, fresh, "uplink PDR");
    else
      insert_or_error(ue_ipv4_hbo2pfcp_pdr, n_ip, fresh, "downlink PDR");
    return;
  }

  // The key moved: file it under the new one before retiring the old.
  if (n_ul) {
    auto p = new_pdr;
    add_pfcp_ul_pdr_by_up_teid(n_teid, p);
  } else {
    auto p = new_pdr;
    add_pfcp_dl_pdr_by_ue_ip(n_ip, p);
  }
  if (o_keyed) remove_pdr_from_lookup(old_pdr);
}

//------------------------------------------------------------------------------
void pfcp_switch::remove_pfcp_ul_pdrs_by_up_teid(const teid_t teid) {
  ul_n3_teid2pfcp_pdr.erase(teid);
}

//------------------------------------------------------------------------------
void pfcp_switch::add_pfcp_dl_pdr_by_ue_ip(
    const uint32_t ue_ip, std::shared_ptr<pfcp::pfcp_pdr>& pdr) {
  // Same copy-on-write rule and the same precedence ordering as the uplink
  // side: a UE has one downlink PDR per QoS flow, all sharing its address, so
  // they must all stay reachable. Replacing the entry would leave only the
  // last, and once SDF filters are enforced that one rejects everything it
  // was not written for.
  auto fresh = std::make_shared<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>();
  const bool is_new = (ue_ipv4_hbo2pfcp_pdr.find(ue_ip) == nullptr);
  {
    oai::upf::rcu_guard g(rcu_);
    const auto* cur = ue_ipv4_hbo2pfcp_pdr.find(ue_ip);
    if (cur)
      for (const auto& e : **cur)
        // A re-sent PDR replaces its older self rather than joining it.
        if (e && !(e->local_seid == pdr->local_seid &&
                   e->pdr_id.rule_id == pdr->pdr_id.rule_id))
          fresh->push_back(e);
  }
  auto at = fresh->begin();
  while (at != fresh->end() && *(*at) < *pdr) ++at;
  fresh->insert(at, pdr);
  insert_or_error(ue_ipv4_hbo2pfcp_pdr, ue_ip, fresh, "downlink PDR");
  if (is_new && !upf_cfg.enable_bpf_datapath && upf_cfg.enable_fr &&
      pdr->pdi.second.framed_route.first) {
    for (const auto& item : pdr->pdi.second.framed_route.second) {
      Logger::pfcp_switch().debug("framed routing ip: %s", item.framed_route);
      fr->addFramedRoute(ue_ip, item);
    }
  }
}

//------------------------------------------------------------------------------
void pfcp_switch::remove_pfcp_dl_pdrs_by_ue_ip(const uint32_t ue_ip) {
  ue_ipv4_hbo2pfcp_pdr.erase(ue_ip);
  if (!upf_cfg.enable_bpf_datapath && upf_cfg.enable_fr) {
    this->fr->remove_entry(ue_ip);
  }
}

//------------------------------------------------------------------------------
std::string pfcp_switch::to_string() const {
  std::string s = {};
  up_seid2pfcp_sessions.for_each(
      [&s](const uint64_t&, const std::shared_ptr<pfcp::pfcp_session>& v) {
        s.append(v->to_string());
      });
  return s;
}

//------------------------------------------------------------------------------
bool pfcp_switch::create_packet_in_access(
    std::shared_ptr<pfcp::pfcp_pdr>& pdr, const pfcp::fteid_t& in,
    uint8_t& cause) {
  cause = CAUSE_VALUE_REQUEST_ACCEPTED;
  add_pfcp_ul_pdr_by_up_teid(in.teid, pdr);
  return true;
}

// =============================================================================
// BPF datapath bridge
// =============================================================================

//------------------------------------------------------------------------------
// call_datapath — invoke a SessionManager CRUD function asynchronously.
// Creates a snapshot copy of the pfcp_session so the datapath is not racing
// against N4 modification events on the live session object.

//------------------------------------------------------------------------------
void pfcp_switch::call_datapath(
    itti_n4_session_establishment_request* establishment_request,
    itti_n4_session_modification_request* modification_request,
    itti_n4_session_deletion_request* deletion_request, pfcp::pfcp_session* s,
    std::shared_ptr<SessionManager> obj,
    SessionOperationResult (SessionManager::*crud_func)(
        std::shared_ptr<pfcp::pfcp_session>,
        itti_n4_session_establishment_request*,
        itti_n4_session_modification_request*,
        itti_n4_session_deletion_request*)) {
  std::shared_ptr<pfcp::pfcp_session> pSession =
      std::make_shared<pfcp::pfcp_session>(*s);

  SessionOperationResult result = (obj.get()->*crud_func)(
      pSession, establishment_request, modification_request, deletion_request);

  // Optional: Log errors
  if (!result.success) {
    Logger::pfcp_switch().error(
        "Datapath operation failed: %s (SEID: 0x%lx)", result.message.c_str(),
        result.seid);
  }
}

// =============================================================================
// N4 session event handlers (3GPP TS 29.244 V17.10.0 §7.5)
// =============================================================================

//------------------------------------------------------------------------------
// handle_pfcp_session_establishment_request — 3GPP TS 29.244 V17.10.0 §7.5.2
// Creates a new pfcp_session, processes Create FAR/PDR/QER IEs, allocates
// an N3 F-TEID (§8.2.3) for uplink PDRs, then registers the session in both
// hash maps (keyed by CP F-SEID §8.2.37 and locally-generated UP SEID).

//------------------------------------------------------------------------------
void pfcp_switch::handle_pfcp_session_establishment_request(
    std::shared_ptr<itti_n4_session_establishment_request> sreq,
    itti_n4_session_establishment_response* resp) {
  bool isBpfAccelerationEnabled = upf_cfg.enable_bpf_datapath;

  itti_n4_session_establishment_request* req = sreq.get();
  pfcp::fseid_t fseid                        = {};
  pfcp::cause_t cause = {.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED};
  pfcp::offending_ie_t offending_ie = {};

  if (req->pfcp_ies.get(fseid)) {  // CP F-SEID §8.2.37 — mandatory IE
    std::shared_ptr<pfcp::pfcp_session> s = {};
    bool exist            = get_pfcp_session_by_cp_fseid(fseid, s);
    pfcp_session* session = nullptr;
    if (not exist) {
      session = new pfcp_session(fseid, generate_seid());

      // ---- Create FARs first (PDR create_far look-up requires them) --------
      for (auto it : req->pfcp_ies.create_fars) {
        create_far& cr_far = it;
        if (not session->create(cr_far, cause, offending_ie.offending_ie)) {
          session->cleanup();
          delete session;
          break;
        }
      }

      // ---- Create PDRs (allocates N3 F-TEID for ACCESS PDRs) ---------------
      if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
        //--------------------------------
        // Process PDR to be created
        cause.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
        for (auto it : req->pfcp_ies.create_pdrs) {
          create_pdr& cr_pdr            = it;
          pfcp::fteid_t allocated_fteid = {};

          pfcp::far_id_t far_id = {};
          if (not cr_pdr.get(far_id)) {
            // should be caught in lower layer
            cause.cause_value         = CAUSE_VALUE_MANDATORY_IE_MISSING;
            offending_ie.offending_ie = PFCP_IE_FAR_ID;
            session->cleanup();
            delete session;
            break;
          }
          // create pdr after create far
          pfcp::create_far cr_far = {};
          if (not req->pfcp_ies.get(far_id, cr_far)) {
            // should be caught in lower layer
            cause.cause_value         = CAUSE_VALUE_MANDATORY_IE_MISSING;
            offending_ie.offending_ie = PFCP_IE_CREATE_FAR;
            session->cleanup();
            delete session;
            break;
          }

          // QERs are parsed whenever QoS is enabled, for either datapath.
          // The simple switch enforces the Maximum Bitrate with a token bucket
          // on TC egress (see qos_mbr.hpp); it used to skip QER IEs entirely
          // because only the BPF datapath could act on them.
          if (upf_cfg.enable_qos) {
            pfcp::qer_id_t qer_id = {};
            if (cr_pdr.get(qer_id)) {
              pfcp::create_qer cr_qer = {};
              if (not req->pfcp_ies.get(qer_id, cr_qer)) {
                cause.cause_value         = CAUSE_VALUE_CONDITIONAL_IE_MISSING;
                offending_ie.offending_ie = PFCP_IE_CREATE_QER;
              }
              session->create(cr_qer, cause, offending_ie.offending_ie);
            }
          }

          if (not session->create(
                  cr_pdr, cause, offending_ie.offending_ie, allocated_fteid)) {
            session->cleanup();
            delete session;
            if (cause.cause_value == CAUSE_VALUE_CONDITIONAL_IE_MISSING) {
              resp->pfcp_ies.set(offending_ie);
            }
            resp->pfcp_ies.set(cause);
            break;
          }
          if (allocated_fteid.v4 || allocated_fteid.v6) {
            pfcp::created_pdr created_pdr = {};
            created_pdr.set(cr_pdr.pdr_id.second);
            created_pdr.set(allocated_fteid);
            resp->pfcp_ies.set(created_pdr);
          }
        }
      }

      // ---- Create URRs (BPF only) — §7.5.2.4 Create URR IE ----------------
      // pfcp_session::create(urr) populates session->urrs so that
      // SessionProgramManager::CreatePipeline can populate urr_config_map and
      // urr_volume_counters_map in the BPF program.
      // enable_urr gate: when URR is disabled, skip SMF-sent Create URR IEs
      // (Open5GS/Free5GC SMFs send URRs regardless of the UPF's local setting).
      if (upf_cfg.enable_urr) {
        if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
          for (auto it : req->pfcp_ies.create_urrs) {
            create_urr& cr_urr = it;
            if (not session->create(cr_urr, cause, offending_ie.offending_ie)) {
              Logger::upf_app().error(
                  "Establish: create(urr) failed, cause=%u", cause.cause_value);
              break;
            }
          }
        }
      }

      // ---- Create BARs (BPF only) — §7.5.2.6 Create BAR IE ----------------
      // pfcp_session::create(bar) populates session->bars so that
      // SessionProgramManager::CreatePipeline can populate bar_config_map.
      // enable_bar gate: skip BAR handling when buffering is disabled.
      if (isBpfAccelerationEnabled && upf_cfg.enable_bar) {
        if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
          // common-src: req->pfcp_ies.create_bar is singular std::pair.
          if (req->pfcp_ies.create_bar.first) {
            const create_bar& cr_bar = req->pfcp_ies.create_bar.second;
            if (not session->create(cr_bar, cause, offending_ie.offending_ie)) {
              Logger::upf_app().error(
                  "Establish: create(bar) failed, cause=%u", cause.cause_value);
            }
          }
        }
      }

      // ---- Create MARs (BPF only) — §7.5.2.8 Create MAR IE ----------------
      // pfcp_session::create(mar) populates session->mars so that
      // SessionProgramManager::CreatePipeline can populate mar_rules_map.

      // enable_mar gate: skip MAR handling when multi-access steering is
      // disabled.
      if (isBpfAccelerationEnabled && upf_cfg.enable_mar) {
        if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
          for (auto it : req->pfcp_ies.create_mars) {
            create_mar& cr_mar = it;
            if (not session->create(cr_mar, cause, offending_ie.offending_ie)) {
              Logger::upf_app().error(
                  "Establish: create(mar) failed, cause=%u", cause.cause_value);
              break;
            }
          }
        }
      }

      if (isBpfAccelerationEnabled) {
        Logger::upf_app().info(
            "Establish datapath: create(pdr(s), far(s), qer(s), urr(s), "
            "bar(s), mar(s))");
        call_datapath(
            req, nullptr, nullptr, session, session_manager,
            &SessionManager::EstablishSession);
      }

      if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
        s = std::shared_ptr<pfcp_session>(session);
        add_pfcp_session_by_cp_fseid(fseid, s);
        add_pfcp_session_by_up_seid(session->seid, s);
        resolve_pdr_qfis(s);
        apply_qos_mbr(s);
        // start_timer_min_commit_interval();
        // start_timer_max_commit_interval();

        pfcp::fseid_t up_fseid = {};
        upf_cfg.get_pfcp_fseid(up_fseid);
        up_fseid.seid = session->get_up_seid();
        resp->pfcp_ies.set(up_fseid);

        // Register session
        pfcp::node_id_t node_id = {};
        req->pfcp_ies.get(node_id);  // Node ID §8.2.38 — optional in response
        pfcp_associations::get_instance().notify_add_session(node_id, fseid);
      }
    } else {
      cause.cause_value = CAUSE_VALUE_REQUEST_REJECTED;
    }
  } else {
    // should be caught in lower layer
    cause.cause_value         = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie.offending_ie = PFCP_IE_F_SEID;
  }

  resp->pfcp_ies.set(cause);
  if ((cause.cause_value == CAUSE_VALUE_MANDATORY_IE_MISSING) ||
      (cause.cause_value == CAUSE_VALUE_CONDITIONAL_IE_MISSING)) {
    resp->pfcp_ies.set(offending_ie);
  }

  if (Logger::should_log(spdlog::level::debug)) {
    // Print PDU session rules table
    up_seid2pfcp_sessions.for_each(
        [](const uint64_t&, const std::shared_ptr<pfcp::pfcp_session>& v) {
          std::cout << v->to_string();
        });
  }
}

//------------------------------------------------------------------------------
// handle_pfcp_session_modification_request — 3GPP TS 29.244 V17.10.0 §7.5.4
// Processes Remove/Create/Update PDR, FAR, QER, URR, BAR IEs in order.

//------------------------------------------------------------------------------
void pfcp_switch::handle_pfcp_session_modification_request(
    std::shared_ptr<itti_n4_session_modification_request> sreq,
    itti_n4_session_modification_response* resp) {
  bool isBpfAccelerationEnabled = upf_cfg.enable_bpf_datapath;

  itti_n4_session_modification_request* req = sreq.get();

  std::shared_ptr<pfcp::pfcp_session> s = {};
  pfcp::fseid_t fseid                   = {};
  pfcp::cause_t cause = {.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED};
  pfcp::offending_ie_t offending_ie = {};
  failed_rule_id_t failed_rule      = {};

  if (not get_pfcp_session_by_up_seid(req->seid, s)) {
    cause.cause_value = CAUSE_VALUE_SESSION_CONTEXT_NOT_FOUND;
  } else {
    pfcp::pfcp_session* session = s.get();
    pfcp::fseid_t fseid         = {};
    if (req->pfcp_ies.get(fseid)) {
      Logger::pfcp_switch().warn(
          "TODO check carefully update fseid in "
          "PFCP_SESSION_MODIFICATION_REQUEST");
      session->cp_fseid = fseid;
    }
    resp->seid = session->cp_fseid.seid;

    // ---- Remove PDRs --------------------------------------------------------
    for (auto it : req->pfcp_ies.remove_pdrs) {
      if (isBpfAccelerationEnabled) {
        Logger::upf_app().info("Modify datapath: remove(pdr)");
        call_datapath(
            nullptr, req, nullptr, session, session_manager,
            &SessionManager::ModifySession);
      }

      remove_pdr& pdr = it;

      // Take it out of the datapath tables first, while the rule is still
      // reachable through the session.
      std::shared_ptr<pfcp::pfcp_pdr> spdr = {};
      if (pdr.pdr_id.first && session->get(pdr.pdr_id.second.rule_id, spdr) &&
          spdr) {
        remove_pdr_from_lookup(spdr);
      }

      if (not session->remove(pdr, cause, offending_ie.offending_ie)) {
        if (cause.cause_value ==
            CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE) {
          failed_rule.rule_id_type  = FAILED_RULE_ID_TYPE_PDR;
          failed_rule.rule_id_value = pdr.pdr_id.second.rule_id;
          resp->pfcp_ies.set(failed_rule);
          break;
        }
      }
    }

    // ---- Remove FARs --------------------------------------------------------
    if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
      for (auto it : req->pfcp_ies.remove_fars) {
        if (isBpfAccelerationEnabled) {
          Logger::upf_app().info("Modify datapath: remove(far)");
          call_datapath(
              nullptr, req, nullptr, session, session_manager,
              &SessionManager::ModifySession);
        }

        remove_far& far = it;

        if (not session->remove(far, cause, offending_ie.offending_ie)) {
          if (cause.cause_value ==
              CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE) {
            failed_rule.rule_id_type  = FAILED_RULE_ID_TYPE_FAR;
            failed_rule.rule_id_value = far.far_id.second.far_id;
            resp->pfcp_ies.set(failed_rule);
            break;
          }
        }
      }
    }

    // ---- Remove QERs (BPF only) ---------------------------------------------
    // Both datapaths handle QERs: BPF via qer_config_map, the simple switch
    // via a token bucket (see apply_qos_mbr).
    if (upf_cfg.enable_qos) {
      if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
        for (auto it : req->pfcp_ies.remove_qers) {
          // Only the BPF datapath has a SessionManager to call: it is null
          // under the simple switch, so calling through it segfaults. The
          // rule removal below is what both datapaths share.
          if (isBpfAccelerationEnabled) {
            Logger::upf_app().info("Modify datapath: remove(qer)");
            call_datapath(
                nullptr, req, nullptr, session, session_manager,
                &SessionManager::ModifySession);
          }
          remove_qer& qer = it;

          if (not session->remove(qer, cause, offending_ie.offending_ie)) {
            if (cause.cause_value ==
                CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE) {
              failed_rule.rule_id_type  = FAILED_RULE_ID_TYPE_QER;
              failed_rule.rule_id_value = qer.qer_id.second.qer_id;
              resp->pfcp_ies.set(failed_rule);
              break;
            }
          }
        }
      }
    }

    // ---- Remove URRs (BPF only) — §7.5.4.8 Remove URR IE -------------------
    // Removes URR from session->urrs so the BPF urr_config_map entry is
    // cleaned up on the next ModifyPipeline call via call_datapath().
    // enable_urr gate (see establishment path).
    if (upf_cfg.enable_urr) {
      if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
        for (auto it : req->pfcp_ies.remove_urrs) {
          remove_urr& urr = it;
          if (not session->remove(urr, cause, offending_ie.offending_ie)) {
            if (cause.cause_value ==
                CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE) {
              failed_rule.rule_id_type  = FAILED_RULE_ID_TYPE_URR;
              failed_rule.rule_id_value = urr.urr_id.second.urr_id;
              resp->pfcp_ies.set(failed_rule);
              break;
            }
          }
        }
      }
    }

    // ---- Remove BARs (BPF only) — §7.5.4.10 Remove BAR IE ------------------
    // Removes BAR from session->bars so the BPF bar_config_map entry is
    // cleaned up on the next ModifyPipeline call via call_datapath().
    // enable_bar gate: skip BAR handling when buffering is disabled.
    if (isBpfAccelerationEnabled && upf_cfg.enable_bar) {
      if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
        // common-src: pfcp_ies.remove_bar is singular std::pair.
        if (req->pfcp_ies.remove_bar.first) {
          const remove_bar& bar = req->pfcp_ies.remove_bar.second;
          if (not session->remove(bar, cause, offending_ie.offending_ie)) {
            if (cause.cause_value ==
                CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE) {
              failed_rule.rule_id_type  = FAILED_RULE_ID_TYPE_BAR;
              failed_rule.rule_id_value = bar.bar_id.second.bar_id;
              resp->pfcp_ies.set(failed_rule);
            }
          }
        }
      }
    }

    // ---- Remove MARs (BPF only) — §7.5.4.15 Remove MAR IE ------------------

    // enable_mar gate: skip MAR handling when multi-access steering is
    // disabled.
    if (isBpfAccelerationEnabled && upf_cfg.enable_mar) {
      if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
        for (auto it : req->pfcp_ies.remove_mars) {
          remove_mar& mar = it;
          if (not session->remove(mar, cause, offending_ie.offending_ie)) {
            if (cause.cause_value ==
                CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE) {
              failed_rule.rule_id_type  = FAILED_RULE_ID_TYPE_MAR;
              failed_rule.rule_id_value = mar.mar_id.second.mar_id;
              resp->pfcp_ies.set(failed_rule);
              break;
            }
          }
        }
      }
    }

    // ---- Create FARs --------------------------------------------------------
    if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
      for (auto it : req->pfcp_ies.create_fars) {
        create_far& cr_far = it;
        if (not session->create(cr_far, cause, offending_ie.offending_ie)) {
          break;
        }
      }
    }

    // ---- Create PDRs --------------------------------------------------------
    if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
      for (auto it : req->pfcp_ies.create_pdrs) {
        create_pdr& cr_pdr = it;

        pfcp::far_id_t far_id = {};
        if (not cr_pdr.get(far_id)) {
          // should be caught in lower layer
          cause.cause_value         = CAUSE_VALUE_MANDATORY_IE_MISSING;
          offending_ie.offending_ie = PFCP_IE_FAR_ID;
          break;
        }
        // A PDR may reference a FAR created earlier in this same session
        std::shared_ptr<pfcp::pfcp_far> existing_far;
        if (not session->get(far_id.far_id, existing_far)) {
          // FAR ID is present but references no FAR in this request or the
          // session: report the Create PDR that could not be created.
          cause.cause_value = CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE;
          failed_rule.rule_id_type  = FAILED_RULE_ID_TYPE_PDR;
          failed_rule.rule_id_value = cr_pdr.pdr_id.second.rule_id;
          resp->pfcp_ies.set(failed_rule);
          break;
        }

        pfcp::fteid_t allocated_fteid = {};
        if (not session->create(
                cr_pdr, cause, offending_ie.offending_ie, allocated_fteid)) {
          if (cause.cause_value == CAUSE_VALUE_CONDITIONAL_IE_MISSING) {
            resp->pfcp_ies.set(offending_ie);
          }
          resp->pfcp_ies.set(cause);
          break;
        }
        pfcp::created_pdr created_pdr = {};
        created_pdr.set(cr_pdr.pdr_id.second);
        if (not allocated_fteid.is_zero()) {
          created_pdr.set(allocated_fteid);
        }
        resp->pfcp_ies.set(created_pdr);
      }
    }

    // ---- Create QERs (BPF only) ---------------------------------------------
    // Both datapaths handle QERs: BPF via qer_config_map, the simple switch
    // via a token bucket (see apply_qos_mbr).
    if (upf_cfg.enable_qos) {
      if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
        for (auto it : req->pfcp_ies.create_qers) {
          create_qer& cr_qer = it;
          if (not session->create(cr_qer, cause, offending_ie.offending_ie)) {
            break;
          }
        }
      }
    }

    // ---- Create URRs (BPF only) — §7.5.4.4 Create URR IE -------------------
    // Populates session->urrs so that SessionProgramManager::ModifyPipeline
    // can write urr_config_map entries for the new URRs.
    // enable_urr gate (see establishment path).
    if (upf_cfg.enable_urr) {
      if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
        for (auto it : req->pfcp_ies.create_urrs) {
          create_urr& cr_urr = it;
          if (not session->create(cr_urr, cause, offending_ie.offending_ie)) {
            break;
          }
        }
      }
    }

    // ---- Create BARs (BPF only) — §7.5.4.6 Create BAR IE -------------------
    // Populates session->bars so that SessionProgramManager::ModifyPipeline
    // can write bar_config_map entries for the new BARs.
    // enable_bar gate: skip BAR handling when buffering is disabled.
    if (isBpfAccelerationEnabled && upf_cfg.enable_bar) {
      if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
        // common-src: pfcp_ies.create_bar is singular std::pair.
        if (req->pfcp_ies.create_bar.first) {
          const create_bar& cr_bar = req->pfcp_ies.create_bar.second;
          if (not session->create(cr_bar, cause, offending_ie.offending_ie)) {
            // create() failed; cause already set inside.
          }
        }
      }
    }

    // ---- Create MARs (BPF only) — §7.5.2.8 Create MAR IE -------------------
    // enable_mar gate: skip MAR handling when multi-access steering is
    // disabled.
    if (isBpfAccelerationEnabled && upf_cfg.enable_mar) {
      if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
        for (auto it : req->pfcp_ies.create_mars) {
          create_mar& cr_mar = it;
          if (not session->create(cr_mar, cause, offending_ie.offending_ie)) {
            break;
          }
        }
      }
    }

    // ---- Update PDRs / FARs / QERs ------------------------------------------
    if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
      for (auto it : req->pfcp_ies.update_pdrs) {
        update_pdr& pdr     = it;
        uint8_t cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
        if (not session->update(pdr, cause_value)) {
          failed_rule_id_t failed_rule = {};
          failed_rule.rule_id_type     = FAILED_RULE_ID_TYPE_PDR;
          failed_rule.rule_id_value    = pdr.pdr_id.second.rule_id;
          resp->pfcp_ies.set(failed_rule);
        }
      }
      for (auto it : req->pfcp_ies.update_fars) {
        update_far& far     = it;
        uint8_t cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
        if (not session->update(far, cause_value)) {
          cause.cause_value            = cause_value;
          failed_rule_id_t failed_rule = {};
          failed_rule.rule_id_type     = FAILED_RULE_ID_TYPE_FAR;
          failed_rule.rule_id_value    = far.far_id.far_id;
          resp->pfcp_ies.set(failed_rule);
        }
      }
      // Both datapaths handle QERs -- see the Create QER block above.
      if (upf_cfg.enable_qos) {
        for (auto it : req->pfcp_ies.update_qers) {
          update_qer& qer     = it;
          uint8_t cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
          if (not session->update(qer, cause_value)) {
            failed_rule_id_t failed_rule = {};
            failed_rule.rule_id_type     = FAILED_RULE_ID_TYPE_QER;
            failed_rule.rule_id_value    = qer.qer_id.second.qer_id;
            resp->pfcp_ies.set(failed_rule);
          }
        }
      }

      // ---- Update URRs (BPF only) — §7.5.4.11 Update URR IE ----------------
      // Updates reporting triggers, thresholds, and quotas in session->urrs.
      // urr_config_map is repopulated by ModifyPipeline;
      // urr_volume_counters_map counters are preserved (BPF_NOEXIST semantics
      // in PopulateUrrConfigMap).
      // enable_urr gate (see establishment path).
      if (upf_cfg.enable_urr) {
        for (auto it : req->pfcp_ies.update_urrs) {
          update_urr& urr     = it;
          uint8_t cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
          if (not session->update(urr, cause_value)) {
            failed_rule_id_t failed_rule = {};
            failed_rule.rule_id_type     = FAILED_RULE_ID_TYPE_URR;
            failed_rule.rule_id_value    = urr.urr_id.second.urr_id;
            resp->pfcp_ies.set(failed_rule);
          }
        }
      }

      // ---- Update BARs (BPF only) — §7.5.4.13 Update BAR IE ----------------
      // Updates DL notification delay and suggested buffering packet count.
      // bar_state_map (DDN tracking) is preserved by ModifyPipeline.
      // enable_bar gate: skip BAR handling when buffering is disabled.
      if (isBpfAccelerationEnabled && upf_cfg.enable_bar) {
        // common-src: pfcp_ies.update_bar is singular std::pair.
        if (req->pfcp_ies.update_bar.first) {
          const update_bar_within_pfcp_session_modification_request& bar =
              req->pfcp_ies.update_bar.second;
          uint8_t cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
          if (not session->update(bar, cause_value)) {
            failed_rule_id_t failed_rule = {};
            failed_rule.rule_id_type     = FAILED_RULE_ID_TYPE_BAR;
            failed_rule.rule_id_value    = bar.bar_id.second.bar_id;
            resp->pfcp_ies.set(failed_rule);
          }
        }
      }

      // ---- Update MARs (BPF only) — §7.5.4.16 Update MAR IE ----------------
      // enable_mar gate: skip MAR handling when multi-access steering is
      // disabled.
      if (isBpfAccelerationEnabled && upf_cfg.enable_mar) {
        for (auto it : req->pfcp_ies.update_mars) {
          update_mar& mar     = it;
          uint8_t cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
          if (not session->update(mar, cause_value)) {
            failed_rule_id_t failed_rule = {};
            failed_rule.rule_id_type     = FAILED_RULE_ID_TYPE_MAR;
            failed_rule.rule_id_value    = mar.mar_id.second.mar_id;
            resp->pfcp_ies.set(failed_rule);
          }
        }
      }
    }

    if (isBpfAccelerationEnabled) {
      Logger::upf_app().info("Modify datapath");
      call_datapath(
          nullptr, req, nullptr, session, session_manager,
          &SessionManager::ModifySession);
    }

    // Re-programme the rate limiters. This is the hook that matters in
    // practice: the downlink FAR only learns its Outer Header Creation TEID
    // once the gNB reports its N3 tunnel, which arrives here and not at
    // establishment.
    resolve_pdr_qfis(s);
    apply_qos_mbr(s);
  }

  resp->pfcp_ies.set(cause);
  if ((cause.cause_value == CAUSE_VALUE_MANDATORY_IE_MISSING) ||
      (cause.cause_value == CAUSE_VALUE_CONDITIONAL_IE_MISSING)) {
    resp->pfcp_ies.set(offending_ie);
  }

  if (Logger::should_log(spdlog::level::debug)) {
    // Print PDU session rules table
    up_seid2pfcp_sessions.for_each(
        [](const uint64_t&, const std::shared_ptr<pfcp::pfcp_session>& v) {
          std::cout << v->to_string();
        });
  }
}

//------------------------------------------------------------------------------
// handle_pfcp_session_deletion_request — 3GPP TS 29.244 V17.10.0 §7.5.6
// Invokes the BPF datapath removal if enabled, then removes the session from
// both hash maps and clears all tun/teid registrations via cleanup().

//------------------------------------------------------------------------------
void pfcp_switch::handle_pfcp_session_deletion_request(
    std::shared_ptr<itti_n4_session_deletion_request> sreq,
    itti_n4_session_deletion_response* resp) {
  bool isBpfAccelerationEnabled         = upf_cfg.enable_bpf_datapath;
  itti_n4_session_deletion_request* req = sreq.get();

  std::shared_ptr<pfcp::pfcp_session> s = {};
  pfcp::fseid_t fseid                   = {};
  pfcp::cause_t cause = {.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED};

  if (not get_pfcp_session_by_up_seid(req->seid, s)) {
    cause.cause_value = CAUSE_VALUE_SESSION_CONTEXT_NOT_FOUND;
  } else {
    pfcp::pfcp_session* session = s.get();
    resp->seid                  = s->cp_fseid.seid;

    if (isBpfAccelerationEnabled) {
      Logger::upf_app().info("Delete datapath");
      call_datapath(
          nullptr, nullptr, req, session, session_manager,
          &SessionManager::RemoveSession);
    }

    remove_pfcp_session(s);
  }

  pfcp_associations::get_instance().notify_del_session(fseid);
  resp->pfcp_ies.set(cause);

  if (Logger::should_log(spdlog::level::debug)) {
    // Print PDU session rules table
    up_seid2pfcp_sessions.for_each(
        [](const uint64_t&, const std::shared_ptr<pfcp::pfcp_session>& v) {
          std::cout << v->to_string();
        });
  }
}

// =============================================================================
// Per-packet data-plane look-up (hot path)
// =============================================================================

//------------------------------------------------------------------------------
// pfcp_session_look_up_pack_in_access (IPv4) — N3 uplink path.
// Looks up the TEID in ul_n3_teid2pfcp_pdr, iterates PDRs in precedence order,
// runs PDI matching, then calls pfcp_far::apply_forwarding_rules().

//------------------------------------------------------------------------------
void pfcp_switch::pfcp_session_look_up_pack_in_access(
    struct iphdr* const iph, const std::size_t num_bytes,
    const endpoint& r_endpoint, const uint32_t tunnel_id, bool released) {
  bool isInAccess = false;
  if (!upf_cfg.nsf.bypass_ul_pfcp_rules) {
    // One RCU critical section covers every pointer this packet touches, so
    // the packet costs two plain stores to this thread's own cache line
    // instead of ~8 atomic RMWs on lines shared with every other core. The
    // two exceptions are the FAR and the meter: the guard keeps the session
    // alive, but a Remove FAR or a modification frees those two out from
    // under a reader, so each is taken by reference rather than borrowed.
    oai::upf::rcu_guard rg(rcu_);
    const auto* pdrs_p = find_ul_pdrs(tunnel_id);
    if (pdrs_p) {
      const auto& pdrs = *pdrs_p;
      bool nocp        = false;
      bool buff        = false;
      for (auto it_pdr = pdrs->begin(); it_pdr < pdrs->end(); ++it_pdr) {
        isInAccess = (*it_pdr)->look_up_pack_in_access(
            iph, num_bytes, r_endpoint, tunnel_id);
        if (!isInAccess && upf_cfg.enable_fr &&
            it_pdr->get()->pdi.second.framed_route.first) {
          // A stack copy of the real header: the framed-route retry only
          // substitutes the source address and every other field must still be
          // the packet's own. This used to malloc() an iphdr that was never
          // freed -- a leak on the per-packet path -- and left all the fields
          // except saddr uninitialised.
          struct iphdr fr_ue_ip = *iph;
          fr_ue_ip.saddr = be32toh(fr->retrieveUEIp(be32toh(iph->saddr)));
          isInAccess     = (*it_pdr)->look_up_pack_in_access(
              &fr_ue_ip, num_bytes, r_endpoint, tunnel_id);
        }
        if (isInAccess) {
          // NOTE: no logging on the per-packet fast path.  These were info()
          // calls, which pass should_log() at the shipped default log level
          // (config.yaml: general: debug) and cost two fmt::sprintf plus a
          // sink write on every uplink packet.
          uint64_t lseid = 0;
          if ((*it_pdr)->get(lseid)) {
            const auto* sess_p = find_session(lseid);
            if (sess_p) {
              const auto& ssession  = *sess_p;
              pfcp::far_id_t far_id = {};
              if ((*it_pdr)->get(far_id)) {
                const auto sfar = ssession->find_far(far_id.far_id);
                if (sfar) {
                  // Maintain uplink QFI in session
                  uint8_t qfi = (*it_pdr)->pdi.second.qfi.second.qfi;
                  ssession->qfi.store(qfi, std::memory_order_relaxed);
                  // Over its MBR: dropped before it is counted, so the
                  // usage report holds what was forwarded (§8.2.8, §8.2.44).
                  // Volume is the decapsulated packet, i.e. what the UE sent.
                  const auto qos = std::atomic_load_explicit(
                      &(*it_pdr)->qos, std::memory_order_acquire);
                  if (qos && !released &&
                      !meter(
                          *qos, (const char*) iph, num_bytes, tunnel_id,
                          &r_endpoint))
                    return;
                  ssession->add_ul(num_bytes);
                  sfar->apply_forwarding_rules(iph, num_bytes, nocp, buff, 0);
                }
              }
            }
            return;
          }

        } else {
          Logger::pfcp_switch().trace(
              "uplink TEID 0x%x: PDR %u does not match this packet, trying "
              "the next by precedence",
              tunnel_id, (*it_pdr)->pdr_id.rule_id);
        }
      }
    } else {
      // Logger::pfcp_switch().info( "pfcp_session_look_up_pack_in_access tunnel
      // " TEID_FMT " not found", tunnel_id);
      upf_n3_inst->report_error_indication(r_endpoint, tunnel_id);
    }
  } else {
    // bypass_ul_pfcp_rules: skip PDR look-up, forward directly to core
    if (no_internal_loop(iph, num_bytes)) {
      pfcp_switch_inst->send_to_core(
          reinterpret_cast<char* const>(iph), num_bytes);
    }
  }
}

//------------------------------------------------------------------------------
bool pfcp_switch::no_internal_loop(
    struct iphdr* const iph, const std::size_t num_bytes) {
  pdn_cfg_t& pdn = upf_cfg.pdns[0];
  if ((pdn.network_ipv4.s_addr == (iph->daddr & pdn.network_mask_ipv4_be)) &&
      ((be32toh(iph->daddr) & 0x000000FF) != 0X00000001)) {
    pfcp_session_look_up_pack_in_core((const char*) iph, num_bytes);
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
// pfcp_session_look_up_pack_in_access (IPv6) — TODO

//------------------------------------------------------------------------------
void pfcp_switch::pfcp_session_look_up_pack_in_access(
    struct ipv6hdr* const ip6h, const std::size_t num_bytes,
    const endpoint& r_endpoint, const uint32_t tunnel_id) {
  // TODO: IPv6 uplink look-up
}

//------------------------------------------------------------------------------
// pfcp_session_look_up_pack_in_core — N6 downlink path.
// Looks up the destination UE IP in ue_ipv4_hbo2pfcp_pdr, iterates PDRs in
// precedence order, then calls pfcp_far::apply_forwarding_rules().

//------------------------------------------------------------------------------
void pfcp_switch::pfcp_session_look_up_pack_in_core(
    const char* buffer, const std::size_t num_bytes, bool released) {
  struct iphdr* iph = (struct iphdr*) buffer;

  // See the uplink path: one critical section, and nothing is refcounted per
  // packet except the FAR and the meter, which the control plane can free
  // while this runs.
  oai::upf::rcu_guard rg(rcu_);

  if (iph->version == 4) {
    uint32_t ue_ip     = be32toh(iph->daddr);
    const auto* pdrs_p = find_dl_pdrs(ue_ip);
    if (!pdrs_p && upf_cfg.enable_fr) {
      const uint32_t fr_ip = fr->retrieveUEIp(ue_ip);
      ue_ip                = fr_ip != 0 ? fr_ip : ue_ip;
      pdrs_p               = find_dl_pdrs(ue_ip);
    }
    if (pdrs_p) {
      const auto* pdrs = pdrs_p->get();
      bool nocp        = false;
      bool buff        = false;
      for (auto it = pdrs->begin(); it < pdrs->end(); ++it) {
        if ((*it)->look_up_pack_in_core(iph, num_bytes)) {
          uint64_t lseid = 0;
          if ((*it)->get(lseid)) {
            const auto* sess_p = find_session(lseid);
            if (sess_p) {
              const auto& ssession  = *sess_p;
              pfcp::far_id_t far_id = {};
              if ((*it)->get(far_id)) {
                // The QFI belongs to the flow this packet matched, so read
                // it from the matched rule, which is immutable once published.
                // Resolving it through the session's QER list instead would
                // mean walking a vector the control plane can be editing.
                // Rules that carry no QFI fall back to the session-wide value
                // learned from uplink traffic.
                uint8_t qfi = ssession->qfi.load(std::memory_order_relaxed);
                if ((*it)->tx_qfi >= 0) qfi = (uint8_t) (*it)->tx_qfi;
                const auto sfar = ssession->find_far(far_id.far_id);
                if (sfar) {
                  // Metered once: a packet coming back out of the shaper
                  // already holds a slot, and asking for a second one would
                  // charge the rate twice and pace it at half.
                  const auto qos = std::atomic_load_explicit(
                      &(*it)->qos, std::memory_order_acquire);
                  if (qos && !released &&
                      !meter(*qos, buffer, num_bytes, 0, nullptr))
                    return;
                  // Counted after the wait, so a report never claims a packet
                  // that is still queued -- or one that was dropped waiting.
                  ssession->add_dl(num_bytes);
                  sfar->apply_forwarding_rules(iph, num_bytes, nocp, buff, qfi);
                  if (buff) {
                    (*it)->buffering_requested(buffer, num_bytes);
                  }
                  if (nocp) {
                    (*it)->notify_cp_requested(ssession);
                  }
                }
              }
            }
          }
          return;
        } else {
          Logger::pfcp_switch().trace(
              "downlink UE %u.%u.%u.%u: PDR %u does not match this packet, "
              "trying the next by precedence",
              (ue_ip >> 24) & 0xff, (ue_ip >> 16) & 0xff, (ue_ip >> 8) & 0xff,
              ue_ip & 0xff, (*it)->pdr_id.rule_id);
        }
      }
    } else {
      Logger::pfcp_switch().trace(
          "downlink: no session owns UE IP %u.%u.%u.%u, packet dropped",
          (ue_ip >> 24) & 0xff, (ue_ip >> 16) & 0xff, (ue_ip >> 8) & 0xff,
          ue_ip & 0xff);
    }
  } else if (iph->version == 6) {
    // TODO: IPv6 downlink look-up
  } else {
    Logger::pfcp_switch().trace(
        "downlink: not an IPv4 or IPv6 packet (version %d), dropped",
        iph->version);
  }
}
