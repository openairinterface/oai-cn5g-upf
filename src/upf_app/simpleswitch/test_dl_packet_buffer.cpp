/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 *
 * Self-check for the DL packet store behind paging. Header-only, so it needs
 * nothing but a compiler:
 *
 *   g++ -std=c++17 -O2 -pthread \
 *       src/upf_app/simpleswitch/test_dl_packet_buffer.cpp \
 *       -o /tmp/test_dl_packet_buffer && /tmp/test_dl_packet_buffer
 *
 * The DN is untrusted and the SMF never says stop, so what has to hold is
 * admission: nothing is held without a record and a current rule, every
 * bound is a hard ceiling however many threads race it, and every packet
 * that got in leaves through exactly one counter.
 */

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <thread>
#include <vector>

#include "dl_packet_buffer.hpp"

using oai::upf::dl_buffer_limits;
using oai::upf::dl_buffer_stats;
using oai::upf::dl_fifo;
using oai::upf::dl_packet;
using oai::upf::dl_packet_buffer;
using oai::upf::dl_verdict;
using oai::upf::find_rearm_target;

namespace {

using clk = dl_packet_buffer::clock;
using std::chrono::milliseconds;

constexpr uint64_t SEID = 0x1001;
constexpr uint64_t UID  = 42;  // an arbitrary rule_uid
constexpr size_t PKT    = 100;

dl_buffer_limits on() {
  dl_buffer_limits l;
  l.enabled = true;
  return l;
}

std::vector<uint8_t> payload(size_t n, uint8_t fill = 0xab) {
  return std::vector<uint8_t>(n, fill);
}

bool put(dl_packet_buffer& b, uint64_t seid, uint64_t uid, size_t n = PKT) {
  const auto p = payload(n);
  return b.enqueue(seid, uid, 7, p.data(), p.size());
}

/// Both closing equations, checked whenever nothing is in flight.
void assert_balanced(const dl_packet_buffer& b) {
  const dl_buffer_stats s = b.stats();
  assert(
      s.stored == s.flushed + s.discarded + s.expired + s.held &&
      "stored != flushed + discarded + expired + held");
  assert(
      s.flushed == s.replay_sent + s.replay_dropped + s.replay_rebuffered &&
      "flushed != replay_sent + replay_dropped + replay_rebuffered");
}

/// Before publish there is no record, so nothing is held -- and no record is
/// created by the attempt.
void test_enqueue_refused_without_record() {
  dl_packet_buffer b(on());
  assert(!put(b, SEID, UID) && "held a packet for an unknown session");
  assert(!b.has_record(SEID) && "an enqueue created a record");
  assert(b.stats().no_record_dropped == 1 && "refusal not counted");
  assert(b.total_pkts() == 0 && b.total_bytes() == 0 && "reservation leaked");

  // With buffering off nothing is held and nothing is counted.
  dl_packet_buffer off;
  off.publish(SEID, {UID});
  assert(!put(off, SEID, UID) && "held a packet with buffering off");
  assert(!off.has_record(SEID) && "publish is not a no-op when off");
  assert(off.stats() == dl_buffer_stats() && "counted with buffering off");
}

/// A uid that is not in `valid` is refused and leaves the FIFO empty.
void test_stale_uid_opens_no_fifo() {
  dl_packet_buffer b(on());
  b.publish(SEID, {});
  assert(!put(b, SEID, UID) && "held under a uid that does not buffer");
  assert(b.held_for(SEID) == 0 && "a stale uid opened a FIFO");
  assert(b.stats().stale_dropped == 1 && "stale refusal not counted");
  assert(b.session_pkts(SEID) == 0 && b.total_pkts() == 0 && "leaked");
}

/// The per-session packet bound is drop-tail: the first N stay, the rest go.
void test_drop_tail_per_session_pkts() {
  dl_buffer_limits l     = on();
  l.max_pkts_per_session = 4;
  dl_packet_buffer b(l);
  b.publish(SEID, {UID});
  for (int i = 0; i < 4; i++) assert(put(b, SEID, UID) && "under the bound");
  assert(!put(b, SEID, UID) && "over the per-session packet bound");
  assert(b.held_for(SEID) == 4 && "not drop-tail");
  assert(b.stats().overflow_dropped == 1 && "overflow not counted");
  // Another session is not charged for this one.
  b.publish(SEID + 1, {UID});
  assert(put(b, SEID + 1, UID) && "one session's bound refused another");
}

/// Bytes are charged by allocated size, not by payload.
void test_drop_tail_per_session_bytes() {
  dl_buffer_limits l = on();
  const uint32_t c   = dl_packet_buffer::charge_of(PKT);
  assert(c > PKT + dl_packet::HEADROOM && "overhead not charged");
  // Room for three allocations -- but for four payloads.
  l.max_bytes_per_session = 3 * c + c / 2;
  assert(l.max_bytes_per_session >= 4 * PKT && "test sizing");
  dl_packet_buffer b(l);
  b.publish(SEID, {UID});
  for (int i = 0; i < 3; i++) assert(put(b, SEID, UID) && "under the bound");
  assert(!put(b, SEID, UID) && "charged by payload, not allocation");
  assert(b.session_bytes(SEID) == 3ULL * c && "session bytes wrong");
  assert(b.total_bytes() == 3ULL * c && "global bytes wrong");
}

/// The global packet bound holds across sessions.
void test_drop_tail_global_pkts() {
  dl_buffer_limits l = on();
  l.max_pkts_total   = 3;
  dl_packet_buffer b(l);
  for (uint64_t s = 1; s <= 4; s++) b.publish(s, {UID});
  for (uint64_t s = 1; s <= 3; s++) assert(put(b, s, UID) && "under bound");
  assert(!put(b, 4, UID) && "over the global packet bound");
  assert(b.session_pkts(4) == 0 && "per-session share not rolled back");
  assert(b.total_pkts() == 3 && "global count wrong");
}

/// The global byte bound holds across sessions, and a refusal rolls back the
/// packet share it took first.
void test_drop_tail_global_bytes() {
  dl_buffer_limits l = on();
  const uint32_t c   = dl_packet_buffer::charge_of(PKT);
  l.max_bytes_total  = 2 * c + c / 2;
  dl_packet_buffer b(l);
  for (uint64_t s = 1; s <= 3; s++) b.publish(s, {UID});
  assert(put(b, 1, UID) && put(b, 2, UID) && "under the bound");
  assert(!put(b, 3, UID) && "over the global byte bound");
  assert(b.total_pkts() == 2 && "packet share not rolled back");
  assert(b.total_bytes() == 2ULL * c && "byte share wrong");
  assert(b.session_pkts(3) == 0 && "per-session share not rolled back");
}

/// Nothing longer than the receive buffer's payload can be replayed, so it is
/// refused before any reservation; so is an empty packet.
void test_oversize_packet_refused() {
  dl_packet_buffer b(on());
  b.publish(SEID, {UID});
  const uint32_t max = b.limits().max_pkt_len;
  assert(put(b, SEID, UID, max) && "the largest packet refused");
  assert(!put(b, SEID, UID, max + 1) && "an oversize packet admitted");
  assert(!put(b, SEID, UID, 0) && "an empty packet admitted");
  assert(b.held_for(SEID) == 1 && "oversize held");
  assert(b.stats().overflow_dropped == 2 && "oversize not counted");
  assert(b.total_pkts() == 1 && "oversize reserved");
}

/// Many DL threads racing the bounds: never over a ceiling, every attempt
/// counted once, and the reservations all come back.
void test_reserve_rollback_threads() {
  dl_buffer_limits l     = on();
  l.max_pkts_per_session = 50;
  l.max_pkts_total       = 120;
  dl_packet_buffer b(l);
  constexpr int SESSIONS = 4, THREADS = 8, EACH = 200;
  for (uint64_t s = 1; s <= SESSIONS; s++) b.publish(s, {UID});

  std::vector<std::thread> ts;
  for (int t = 0; t < THREADS; t++)
    ts.emplace_back([&b, t] {
      for (int i = 0; i < EACH; i++)
        put(b, 1 + (uint64_t) ((t + i) % SESSIONS), UID);
    });
  for (auto& t : ts) t.join();

  const dl_buffer_stats s = b.stats();
  assert(
      s.stored + s.overflow_dropped == (uint64_t) THREADS * EACH &&
      "an attempt was lost or double counted");
  assert(s.stored <= l.max_pkts_total && "global bound exceeded");
  uint64_t sum = 0;
  for (uint64_t x = 1; x <= SESSIONS; x++) {
    assert(b.held_for(x) <= l.max_pkts_per_session && "session bound exceeded");
    assert(b.session_pkts(x) == b.held_for(x) && "session share leaked");
    sum += b.held_for(x);
  }
  assert(sum == s.stored && b.total_pkts() == sum && "global share leaked");

  for (uint64_t x = 1; x <= SESSIONS; x++)
    b.detach_and_rearm(x, {}, dl_verdict::discard);
  assert(b.total_pkts() == 0 && b.total_bytes() == 0 && "not released");
  assert_balanced(b);
}

/// The copy keeps the GTP-U headroom in front, and the bytes.
void test_headroom_preserved() {
  dl_packet_buffer b(on());
  b.publish(SEID, {UID});
  std::vector<uint8_t> p(PKT);
  for (size_t i = 0; i < p.size(); i++) p[i] = (uint8_t) i;
  assert(b.enqueue(SEID, UID, 9, p.data(), p.size()) && "refused");
  dl_fifo out = b.detach_and_rearm(SEID, {}, dl_verdict::flush);
  assert(out.size() == 1 && "not detached");
  const dl_packet& e = out.front();
  assert(e.data() - e.buf.get() == 64 && "headroom lost");
  assert(e.len == PKT && e.pdr_id == 9 && e.rule_uid == UID && "metadata");
  assert(std::memcmp(e.data(), p.data(), PKT) == 0 && "payload changed");
}

/// A Tombstone refuses everything, and gc() erases it only once it is old.
void test_tombstone_refuses_and_gc() {
  dl_packet_buffer b(on());
  b.publish(SEID, {UID});
  assert(put(b, SEID, UID) && put(b, SEID, UID) && "refused");
  const auto t0 = clk::now();
  assert(b.tombstone(SEID, t0) == 2 && "FIFO not discarded");
  assert(b.total_pkts() == 0 && b.total_bytes() == 0 && "not released");
  assert(!put(b, SEID, UID) && "a Tombstone admitted a straggler");
  assert(b.stats().tombstone_dropped == 1 && "straggler not counted");
  assert(b.tombstone(SEID, t0) == 0 && "tombstoned twice");

  assert(b.gc(t0 + milliseconds(999)) == 0 && "collected too early");
  assert(b.has_record(SEID) && "Tombstone gone too early");
  assert(b.gc(t0 + milliseconds(1000)) == 1 && "not collected");
  assert(!b.has_record(SEID) && "Tombstone not erased");
  assert(!put(b, SEID, UID) && b.stats().no_record_dropped == 1 && "gone");
  assert_balanced(b);
}

/// Detach on a Tombstone neither reopens it nor returns anything.
void test_detach_on_tombstone_is_noop() {
  dl_packet_buffer b(on());
  b.publish(SEID, {UID});
  b.tombstone(SEID);
  const uint64_t g = b.generation(SEID);
  assert(
      b.detach_and_rearm(SEID, {UID}, dl_verdict::keep).empty() &&
      "detached from a Tombstone");
  assert(b.generation(SEID) == g && "a Tombstone was re-armed");
  assert(!put(b, SEID, UID) && "detach reopened a Tombstone");
  // On a missing record it creates nothing.
  assert(b.detach_and_rearm(SEID + 1, {UID}, dl_verdict::flush).empty());
  assert(!b.has_record(SEID + 1) && "detach created a record");
}

/// A late publish cannot bring a Tombstone back to life.
void test_publish_on_tombstone_is_noop() {
  dl_packet_buffer b(on());
  b.publish(SEID, {});
  b.tombstone(SEID);
  b.publish(SEID, {UID});
  assert(b.is_tombstone(SEID) && "publish reopened a Tombstone");
  assert(!put(b, SEID, UID) && "publish made a Tombstone admit");
}

/// T_guard (the maximum hold time) discards FIFOs whose oldest packet has
/// waited long enough, and returns the uids to re-arm; younger FIFOs and the
/// episode stay.
void test_expire_returns_uids() {
  dl_packet_buffer b(on());
  const auto t0 = clk::now();
  const auto p  = payload(PKT);
  b.publish(1, {10, 11});
  b.publish(2, {20});
  assert(b.enqueue(1, 10, 1, p.data(), PKT, t0) && "refused");
  assert(b.enqueue(1, 11, 2, p.data(), PKT, t0 + milliseconds(5)) && "");
  assert(b.enqueue(1, 10, 1, p.data(), PKT, t0 + milliseconds(6)) && "");
  assert(b.enqueue(2, 20, 1, p.data(), PKT, t0 + milliseconds(500)) && "");

  assert(b.expire(t0 + milliseconds(999), milliseconds(1000)).empty());
  auto x = b.expire(t0 + milliseconds(1000), milliseconds(1000));
  assert(x.size() == 1 && x[0].seid == 1 && "wrong FIFO expired");
  assert(x[0].discarded == 3 && "whole FIFO not discarded");
  assert(x[0].uids.size() == 2 && "uids not deduplicated");
  assert(
      ((x[0].uids[0] == 10 && x[0].uids[1] == 11) ||
       (x[0].uids[0] == 11 && x[0].uids[1] == 10)) &&
      "wrong uids");
  assert(x[0].pdr_ids.size() == 2 && "one PDR ID per uid");
  for (size_t i = 0; i < 2; i++)
    assert(
        x[0].pdr_ids[i] == (x[0].uids[i] == 10 ? 1 : 2) &&
        "PDR ID not paired with its uid");
  assert(b.held_for(1) == 0 && b.held_for(2) == 1 && "wrong FIFO emptied");
  assert(b.stats().expired == 3 && "expired not counted");
  assert(b.session_pkts(1) == 0 && "not released");
  // The episode stays open: the next packet is held again.
  assert(put(b, 1, 10) && "expire closed the episode");
  assert_balanced(b);
}

/// A failed DDN (Downlink Data Notification) is retried once per take:
/// deduplicated, drained whole, and dropped when the session is gone.
void test_ddn_retry_once_per_take() {
  dl_packet_buffer b(on());
  b.publish(1, {10});
  b.publish(2, {20});
  // true means "the latch may stay held": a mark is stored, or none is
  // needed. Only an allocation failure returns false.
  bool held = b.mark_ddn_failed(1, 10, 1);
  assert(held && "first mark refused");
  held = b.mark_ddn_failed(1, 10, 1);
  assert(held && "duplicate mark refused");
  b.mark_ddn_failed(2, 20, 2);
  auto r = b.take_ddn_retries();
  assert(r.size() == 2 && "not deduplicated per (seid, uid)");
  assert(b.take_ddn_retries().empty() && "not drained");

  // Marks on a missing record are dropped with buffering on...
  held = b.mark_ddn_failed(99, 1, 0);
  assert(held && "latch released for a missing record");
  assert(b.take_ddn_retries().empty() && "mark kept for a missing record");
  // ...on a Tombstone, and by tombstone() itself.
  b.mark_ddn_failed(1, 10, 1);
  b.tombstone(1);
  held = b.mark_ddn_failed(1, 10, 1);
  assert(held && "latch released on a Tombstone");
  assert(b.take_ddn_retries().empty() && "mark kept on a Tombstone");
  // Nothing is left for a SEID once tombstone() and gc() are through with it.
  b.mark_ddn_failed(2, 20, 2);
  b.tombstone(2, clk::now() - milliseconds(2000));
  b.gc(clk::now());
  assert(b.take_ddn_retries().empty() && "mark survived gc");

  // With buffering off there are no records, and the marks still work.
  dl_packet_buffer off;
  held = off.mark_ddn_failed(5, 50, 5);
  assert(held && "mark refused with buffering off");
  off.mark_ddn_failed(5, 50, 5);
  r = off.take_ddn_retries();
  assert(
      r.size() == 1 && r[0].seid == 5 && r[0].uid == 50 && r[0].pdr_id == 5 &&
      "off");
  assert(off.take_ddn_retries().empty() && "not drained with buffering off");
}

/// Just the two fields find_rearm_target() reads, named as in pfcp_pdr.
struct rule {
  uint64_t rule_uid;
  struct {
    uint16_t rule_id;
  } pdr_id;
};

/// An Update PDR replaces the rule by a copy with a fresh uid that inherits
/// the held latch: a retry marked under the old uid still finds it, by PDR
/// ID, as long as the uid itself is gone. With buffering off nothing else
/// would ever release that latch.
void test_rearm_target_falls_back_to_pdr_id() {
  std::vector<std::shared_ptr<rule>> rules = {
      nullptr, std::make_shared<rule>(rule{10, {1}}),
      std::make_shared<rule>(rule{11, {2}})};
  // The uid wins, even over another rule's PDR ID.
  assert(find_rearm_target(rules, 11, uint16_t{1}) == rules[2].get());
  assert(find_rearm_target(rules, 10, std::nullopt) == rules[1].get());
  // The mark carries the PDR ID it was sent for.
  dl_packet_buffer off;
  off.mark_ddn_failed(SEID, 11, 2);
  auto m = off.take_ddn_retries();
  assert(m.size() == 1 && m[0].pdr_id == 2 && "PDR ID not kept");
  // Update PDR: rule 2 is now a copy with uid 12.
  rules[2] = std::make_shared<rule>(rule{12, {2}});
  assert(
      find_rearm_target(rules, m[0].uid, m[0].pdr_id) == rules[2].get() &&
      "COW copy not found by PDR ID");
  // Remove PDR: nothing to re-arm.
  rules.pop_back();
  assert(!find_rearm_target(rules, m[0].uid, m[0].pdr_id) && "stale match");
  assert(!find_rearm_target(rules, 12, std::nullopt) && "unknown uid");
}

/// A rejected Session Modification Request can have applied an Update PDR to
/// the paging PDR before a later IE failed: the copy (fresh uid) inherits the
/// held latch while `valid` still lists the old uid. T_guard then has to find
/// the copy by the PDR ID of what it discarded, or nothing would ever notify
/// the SMF again.
void test_expire_rearm_falls_back_to_pdr_id() {
  dl_packet_buffer b(on());
  const auto t0 = clk::now();
  const auto p  = payload(PKT);
  b.publish(1, {10});
  assert(b.enqueue(1, 10, 5, p.data(), PKT, t0) && "refused");
  // The rejected request: PDR 5 is now a copy with uid 11, and no detach ran.
  std::vector<std::shared_ptr<rule>> rules = {
      std::make_shared<rule>(rule{11, {5}})};
  auto x = b.expire(t0 + milliseconds(1000), milliseconds(1000));
  assert(x.size() == 1 && x[0].uids.size() == 1 && "not expired");
  assert(x[0].uids[0] == 10 && x[0].pdr_ids[0] == 5 && "wrong key");
  assert(
      find_rearm_target(rules, x[0].uids[0], x[0].pdr_ids[0]) ==
          rules[0].get() &&
      "copy not found by PDR ID");
  assert(!find_rearm_target(rules, x[0].uids[0], std::nullopt) && "uid only");
  assert_balanced(b);
}

/// Every packet that got in leaves through exactly one counter.
void test_counters_balance() {
  dl_packet_buffer b(on());
  b.publish(1, {10});
  b.publish(2, {20});
  b.publish(3, {30});
  b.publish(4, {40});
  for (int i = 0; i < 3; i++) put(b, 1, 10);
  for (int i = 0; i < 2; i++) put(b, 2, 20);
  put(b, 3, 30, PKT);
  const auto p = payload(PKT);
  b.enqueue(4, 40, 1, p.data(), PKT, clk::now() - milliseconds(30000));
  put(b, 1, 99);  // stale: counted, not stored
  assert_balanced(b);

  dl_fifo f = b.detach_and_rearm(1, {}, dl_verdict::flush);
  b.note_replay(oai::upf::dl_outcome::sent);
  b.note_replay(oai::upf::dl_outcome::dropped);
  b.note_replay(oai::upf::dl_outcome::rebuffered);
  assert(f.size() == 3 && "flush");
  b.detach_and_rearm(2, {}, dl_verdict::discard);
  b.tombstone(3);
  b.expire(clk::now(), milliseconds(20000));
  const dl_buffer_stats s = b.stats();
  assert(s.flushed == 3 && s.discarded == 3 && s.expired == 1 && "counters");
  assert(s.held == 0 && b.total_pkts() == 0 && "held after everything left");
  assert_balanced(b);
}

}  // namespace

int main() {
  test_enqueue_refused_without_record();
  test_stale_uid_opens_no_fifo();
  test_drop_tail_per_session_pkts();
  test_drop_tail_per_session_bytes();
  test_drop_tail_global_pkts();
  test_drop_tail_global_bytes();
  test_oversize_packet_refused();
  test_reserve_rollback_threads();
  test_headroom_preserved();
  test_tombstone_refuses_and_gc();
  test_detach_on_tombstone_is_noop();
  test_publish_on_tombstone_is_noop();
  test_expire_returns_uids();
  test_ddn_retry_once_per_take();
  test_rearm_target_falls_back_to_pdr_id();
  test_expire_rearm_falls_back_to_pdr_id();
  test_counters_balance();
  printf("dl_packet_buffer: ok\n");
  return 0;
}
