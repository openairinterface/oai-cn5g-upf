/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 *
 * Self-check for the end of a Session Modification: the verdict, and
 * detach_and_rearm(), the one place an episode reopens. Header-only:
 *
 *   g++ -std=c++17 -O2 -pthread src/upf_app/simpleswitch/test_dl_flush.cpp \
 *       -o /tmp/test_dl_flush && /tmp/test_dl_flush
 *
 * The SMF removes the paging PDR and its FAR in one message and creates the
 * forwarding rules beside them, so the flush must win over the removal, keep
 * the order, and hand each packet out exactly once -- while DL threads keep
 * enqueueing, and while a reservation straddles the detach.
 */

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <set>
#include <thread>
#include <vector>

#include "dl_packet_buffer.hpp"

using oai::upf::dl_buffer_limits;
using oai::upf::dl_buffer_stats;
using oai::upf::dl_fifo;
using oai::upf::dl_outcome;
using oai::upf::dl_packet;
using oai::upf::dl_packet_buffer;
using oai::upf::dl_reservation;
using oai::upf::dl_signals;
using oai::upf::dl_verdict;
using oai::upf::verdict_of;

namespace {

using clk = dl_packet_buffer::clock;
using std::chrono::milliseconds;

constexpr uint64_t SEID       = 0x2002;
constexpr uint64_t PAGING_UID = 100;  // arbitrary rule_uids
constexpr uint64_t OTHER_UID  = 200;
constexpr uint64_t NEW_UID    = 300;
constexpr size_t PKT          = 64;

dl_buffer_limits on() {
  dl_buffer_limits l;
  l.enabled = true;
  return l;
}

/// A packet whose first 4 bytes are `seq`, so order and identity survive.
bool put_seq(dl_packet_buffer& b, uint64_t seid, uint64_t uid, uint32_t seq) {
  uint8_t p[PKT] = {};
  std::memcpy(p, &seq, sizeof(seq));
  return b.enqueue(seid, uid, 1, p, sizeof(p));
}

uint32_t seq_of(const dl_packet& e) {
  uint32_t s;
  std::memcpy(&s, e.data(), sizeof(s));
  return s;
}

void assert_balanced(const dl_packet_buffer& b) {
  const dl_buffer_stats s = b.stats();
  assert(
      s.stored == s.flushed + s.discarded + s.expired + s.held &&
      "stored != flushed + discarded + expired + held");
  assert(
      s.flushed == s.replay_sent + s.replay_dropped + s.replay_rebuffered &&
      "flushed != replay_sent + replay_dropped + replay_rebuffered");
}

/// All 8 signal combinations, with and without a buffering FAR left.
void test_verdict_table() {
  for (int m = 0; m < 8; m++) {
    for (int left = 0; left < 2; left++) {
      dl_signals s;
      s.buff_pdr_removed = m & 1;
      s.buff_far_removed = m & 2;
      s.buff_to_forw     = m & 4;
      dl_verdict want;
      if (s.buff_far_removed || s.buff_to_forw)
        want = dl_verdict::flush;
      else if (s.buff_pdr_removed || !left)
        want = dl_verdict::discard;
      else
        want = dl_verdict::keep;
      assert(verdict_of(s, left) == want && "verdict table");
    }
  }
}

/// The Session Modification that ends buffering ("M4" in the assert text
/// below) removes the paging PDR and its FAR in one message: FLUSH.
void test_flush_beats_remove_pdr() {
  dl_signals s;
  s.buff_pdr_removed = true;
  s.buff_far_removed = true;
  assert(verdict_of(s, false) == dl_verdict::flush && "M4 is not a flush");
  dl_signals t;
  t.buff_pdr_removed = true;
  t.buff_to_forw     = true;
  assert(verdict_of(t, true) == dl_verdict::flush && "BUFF->FORW lost");
}

/// Nothing buffers any more and nothing can deliver: DISCARD.
void test_discard_when_no_buff_far_left() {
  assert(verdict_of(dl_signals(), false) == dl_verdict::discard);
  dl_signals s;
  s.buff_pdr_removed = true;
  assert(verdict_of(s, true) == dl_verdict::discard && "Remove PDR alone");
}

/// The Session Modification of a network-triggered Service Request that only
/// creates UL rules ("M3" in the assert text) leaves the episode running.
void test_keep_when_only_unrelated_rules_change() {
  assert(verdict_of(dl_signals(), true) == dl_verdict::keep && "M3 not KEEP");
}

/// FLUSH hands out the whole FIFO, in arrival order, and empties the record.
void test_flush_detaches_all_in_order() {
  dl_packet_buffer b(on());
  b.publish(SEID, {PAGING_UID});
  for (uint32_t i = 0; i < 10; i++) assert(put_seq(b, SEID, PAGING_UID, i));
  dl_fifo out = b.detach_and_rearm(SEID, {}, dl_verdict::flush);
  assert(out.size() == 10 && "not all detached");
  for (uint32_t i = 0; i < 10; i++)
    assert(seq_of(out[i]) == i && "flush reordered");
  assert(b.held_for(SEID) == 0 && b.session_pkts(SEID) == 0 && "left over");
  assert(b.stats().flushed == 10 && b.stats().held == 0 && "counters");
  for (size_t i = 0; i < out.size(); i++) b.note_replay(dl_outcome::sent);
  assert_balanced(b);
}

/// DISCARD hands out everything too, counted as discarded.
void test_discard_detaches_all() {
  dl_packet_buffer b(on());
  b.publish(SEID, {PAGING_UID, OTHER_UID});
  for (uint32_t i = 0; i < 4; i++)
    put_seq(b, SEID, i % 2 ? OTHER_UID : PAGING_UID, i);
  dl_fifo out = b.detach_and_rearm(SEID, {}, dl_verdict::discard);
  assert(out.size() == 4 && "not all detached");
  assert(b.stats().discarded == 4 && b.stats().flushed == 0 && "counters");
  assert(b.total_pkts() == 0 && b.total_bytes() == 0 && "not released");
  assert_balanced(b);
}

/// KEEP keeps the entries of rules that still buffer, in their order, and
/// returns only the others.
void test_keep_filters_in_place_order_kept() {
  dl_packet_buffer b(on());
  b.publish(SEID, {PAGING_UID, OTHER_UID});
  for (uint32_t i = 0; i < 8; i++)
    put_seq(b, SEID, i % 2 ? OTHER_UID : PAGING_UID, i);
  dl_fifo out = b.detach_and_rearm(SEID, {PAGING_UID}, dl_verdict::keep);
  assert(out.size() == 4 && "wrong entries removed");
  for (const auto& e : out) assert(e.rule_uid == OTHER_UID && "kept removed");
  assert(b.held_for(SEID) == 4 && "wrong entries kept");
  assert(b.stats().discarded == 4 && "KEEP-removed not counted");

  // What stayed is still in order: flush it and look.
  dl_fifo rest = b.detach_and_rearm(SEID, {}, dl_verdict::flush);
  assert(rest.size() == 4 && "kept entries lost");
  for (uint32_t i = 0; i < 4; i++)
    assert(seq_of(rest[i]) == 2 * i && "KEEP reordered");
}

/// After a detach the old uid no longer admits anything.
void test_detach_retires_stale_uids() {
  dl_packet_buffer b(on());
  b.publish(SEID, {PAGING_UID});
  put_seq(b, SEID, PAGING_UID, 0);
  b.detach_and_rearm(SEID, {}, dl_verdict::flush);
  assert(!put_seq(b, SEID, PAGING_UID, 1) && "a retired uid admitted");
  assert(b.held_for(SEID) == 0 && "a stale uid opened a FIFO");
  assert(b.stats().stale_dropped == 1 && "stale not counted");
}

/// The next episode's uid is admitted once detach_and_rearm lists it.
void test_new_uid_accepted_after_rearm() {
  dl_packet_buffer b(on());
  b.publish(SEID, {});
  assert(!put_seq(b, SEID, NEW_UID, 0) && "admitted before the re-arm");
  b.detach_and_rearm(SEID, {NEW_UID}, dl_verdict::keep);
  assert(put_seq(b, SEID, NEW_UID, 1) && "new uid refused after the re-arm");
  assert(b.held_for(SEID) == 1 && "not held");
}

/// A replayed packet that matches a BUFF PDR again (the UE went idle again
/// in the same message) joins the new episode, and cannot loop: the FIFO
/// being replayed was already detached.
void test_reidle_during_replay_joins_new_episode() {
  dl_packet_buffer b(on());
  b.publish(SEID, {PAGING_UID});
  for (uint32_t i = 0; i < 3; i++) put_seq(b, SEID, PAGING_UID, i);
  dl_fifo out = b.detach_and_rearm(SEID, {NEW_UID}, dl_verdict::flush);
  for (const auto& e : out) {
    // The re-lookup lands on the new BUFF PDR, whose uid is NEW_UID.
    const bool held = b.enqueue(SEID, NEW_UID, 2, e.data(), e.len);
    assert(held && "re-idle refused");
    b.note_replay(dl_outcome::rebuffered);
  }
  assert(b.held_for(SEID) == 3 && "not in the new episode");
  assert(out.size() == 3 && "the replay grew its own list");
  const dl_buffer_stats s = b.stats();
  assert(s.replay_rebuffered == 3 && s.stored == 6 && "counters");
  assert_balanced(b);
}

/// Each detach is a new generation, whatever the verdict.
void test_gen_bumps_on_each_detach() {
  dl_packet_buffer b(on());
  b.publish(SEID, {PAGING_UID});
  const uint64_t g0 = b.generation(SEID);
  b.detach_and_rearm(SEID, {PAGING_UID}, dl_verdict::keep);
  b.detach_and_rearm(SEID, {}, dl_verdict::flush);
  b.detach_and_rearm(SEID, {}, dl_verdict::discard);
  assert(b.generation(SEID) == g0 + 3 && "generation not bumped");
}

/// DL threads enqueue while TASK_UPF_APP flushes and re-arms in a loop: no
/// packet is handed out twice or lost, and the counters close.
void test_enqueue_races_detach() {
  dl_buffer_limits l     = on();
  l.max_pkts_per_session = 1024;
  l.max_pkts_total       = 4096;
  dl_packet_buffer b(l);
  b.publish(SEID, {PAGING_UID});
  constexpr int THREADS = 4, EACH = 5000;
  std::atomic<int> running{THREADS};
  std::atomic<uint64_t> accepted{0};

  std::vector<std::thread> ts;
  for (int t = 0; t < THREADS; t++)
    ts.emplace_back([&, t] {
      for (int i = 0; i < EACH; i++)
        if (put_seq(b, SEID, PAGING_UID, (uint32_t) (t * EACH + i)))
          accepted.fetch_add(1);
      running.fetch_sub(1);
    });

  std::set<uint32_t> seen;
  auto drain = [&](dl_fifo&& f) {
    for (const auto& e : f) {
      assert(seen.insert(seq_of(e)).second && "a packet detached twice");
      b.note_replay(dl_outcome::sent);
    }
  };
  while (running.load() > 0)
    drain(b.detach_and_rearm(SEID, {PAGING_UID}, dl_verdict::flush));
  for (auto& t : ts) t.join();
  drain(b.detach_and_rearm(SEID, {PAGING_UID}, dl_verdict::flush));

  assert(seen.size() == accepted.load() && "a linked packet was lost");
  const dl_buffer_stats s = b.stats();
  assert(s.stored == accepted.load() && s.flushed == s.stored && "counters");
  assert(b.total_pkts() == 0 && b.session_pkts(SEID) == 0 && "leaked");
  assert_balanced(b);
}

/// A reservation that straddles a FLUSH which retires its uid is refused at
/// commit, and gives both shares back.
void test_commit_after_detach_refused() {
  dl_packet_buffer b(on());
  b.publish(SEID, {PAGING_UID});
  const uint8_t pkt[PKT] = {};
  dl_reservation r       = b.prepare_enqueue(SEID, PAGING_UID, PKT);
  assert(r && b.session_pkts(SEID) == 1 && b.total_pkts() == 1 && "prepare");
  dl_packet p;
  p.buf.reset(new uint8_t[dl_packet::HEADROOM + PKT]);
  std::memcpy(p.data(), pkt, PKT);
  p.len      = PKT;
  p.charged  = r.charged;
  p.rule_uid = r.uid;

  b.detach_and_rearm(SEID, {NEW_UID}, dl_verdict::flush);
  assert(!b.commit_enqueue(r, std::move(p)) && "linked under a retired uid");
  assert(p.buf && "refused packet was taken");
  assert(b.stats().stale_dropped == 1 && "not counted as stale");
  assert(b.session_pkts(SEID) == 0 && b.session_bytes(SEID) == 0 && "session");
  assert(b.total_pkts() == 0 && b.total_bytes() == 0 && "global");
  assert(b.held_for(SEID) == 0 && b.stats().stored == 0 && "linked");
}

/// The same across a tombstone: refused, counted once, shares back.
void test_commit_after_tombstone_refused() {
  dl_packet_buffer b(on());
  b.publish(SEID, {PAGING_UID});
  dl_reservation r = b.prepare_enqueue(SEID, PAGING_UID, PKT);
  assert(r && "prepare");
  dl_packet p;
  p.buf.reset(new uint8_t[dl_packet::HEADROOM + PKT]);
  p.len = PKT;
  b.tombstone(SEID);
  assert(!b.commit_enqueue(r, std::move(p)) && "linked into a Tombstone");
  const dl_buffer_stats s = b.stats();
  assert(s.tombstone_dropped == 1 && s.stale_dropped == 0 && "counted once");
  assert(b.session_pkts(SEID) == 0 && b.total_pkts() == 0 && "shares");
  assert(b.total_bytes() == 0 && "bytes");
}

/// Across a tombstone and its gc: the record, and its per-session share, are
/// gone, so only the global share is given back.
void test_commit_after_gc_refused() {
  dl_packet_buffer b(on());
  b.publish(SEID, {PAGING_UID});
  dl_reservation r = b.prepare_enqueue(SEID, PAGING_UID, PKT);
  assert(r && "prepare");
  dl_packet p;
  p.buf.reset(new uint8_t[dl_packet::HEADROOM + PKT]);
  p.len         = PKT;
  const auto t0 = clk::now();
  b.tombstone(SEID, t0);
  assert(b.gc(t0 + milliseconds(1000)) == 1 && !b.has_record(SEID) && "gc");
  assert(!b.commit_enqueue(r, std::move(p)) && "linked with no record");
  const dl_buffer_stats s = b.stats();
  assert(s.no_record_dropped == 1 && s.tombstone_dropped == 0 && "counted");
  assert(b.total_pkts() == 0 && b.total_bytes() == 0 && "global share kept");
  assert(!b.has_record(SEID) && "commit recreated the record");
}

}  // namespace

int main() {
  test_verdict_table();
  test_flush_beats_remove_pdr();
  test_discard_when_no_buff_far_left();
  test_keep_when_only_unrelated_rules_change();
  test_flush_detaches_all_in_order();
  test_discard_detaches_all();
  test_keep_filters_in_place_order_kept();
  test_detach_retires_stale_uids();
  test_new_uid_accepted_after_rearm();
  test_reidle_during_replay_joins_new_episode();
  test_gen_bumps_on_each_detach();
  test_enqueue_races_detach();
  test_commit_after_detach_refused();
  test_commit_after_tombstone_refused();
  test_commit_after_gc_refused();
  printf("dl_flush: ok\n");
  return 0;
}
