/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef DL_PACKET_BUFFER_HPP_SEEN
#define DL_PACKET_BUFFER_HPP_SEEN

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <new>
#include <unordered_map>
#include <utility>
#include <vector>

namespace oai::upf {

/**
 * @brief What to do with a session's held DL packets at the end of an N4
 * Session Modification.
 *
 * FLUSH replays them through the DL lookup against the new rules, DISCARD
 * frees them, KEEP leaves those still owned by a buffering rule in place and
 * discards the others.
 */
enum class dl_verdict { keep, flush, discard };

inline const char* to_string(dl_verdict v) {
  switch (v) {
    case dl_verdict::flush:
      return "FLUSH";
    case dl_verdict::discard:
      return "DISCARD";
    case dl_verdict::keep:
      return "KEEP";
  }
  return "KEEP";
}

/// What one Session Modification did to the buffering rules. Each flag is set
/// only after the matching removal or update has succeeded.
struct dl_signals {
  /// a Remove PDR IE deleted a PDR whose FAR has Apply Action BUFF
  bool buff_pdr_removed = false;
  /// a Remove FAR IE deleted a FAR with Apply Action BUFF
  bool buff_far_removed = false;
  /// an Update FAR IE changed a FAR from BUFF to FORW (§5.2.4.2)
  bool buff_to_forw = false;
};

/**
 * @brief The verdict, as a pure function of the signals.
 *
 * - FLUSH: an Update FAR turned the buffering FAR into FORW (TS 29.244
 *   §5.2.4.2: buffered packets are dropped or forwarded), or the buffering FAR
 *   was removed (OAI SMF convention: it removes the paging FAR and creates the
 *   new rules in the same message). FLUSH wins over Remove PDR, which the OAI
 *   SMF sends in the same message.
 * - DISCARD: the buffering PDR was removed, or no buffering PDR is left.
 * - KEEP: anything else.
 *
 * @param buffering_pdr_left some PDR still uses a buffering FAR.
 */
inline dl_verdict verdict_of(const dl_signals& s, bool buffering_pdr_left) {
  if (s.buff_far_removed || s.buff_to_forw) return dl_verdict::flush;
  if (s.buff_pdr_removed || !buffering_pdr_left) return dl_verdict::discard;
  return dl_verdict::keep;
}

/// What the DL lookup did with one replayed packet.
enum class dl_outcome { sent, dropped, rebuffered };

/**
 * @brief One held packet: a private copy with the GTP-U headroom in front.
 *
 * The headroom is what lets the replay hand data() to the normal DL path:
 * send_g_pdu writes the GTP-U header in front of the payload, exactly as it
 * does with the receive buffers.
 */
struct dl_packet {
  static constexpr size_t HEADROOM = 64;  ///< = ROOM_FOR_GTPV1U_G_PDU

  std::unique_ptr<uint8_t[]> buf;  ///< HEADROOM + len bytes
  uint32_t len = 0;
  /// bytes charged against the bounds (allocated size, see charge_of())
  uint32_t charged  = 0;
  uint64_t rule_uid = 0;
  uint16_t pdr_id   = 0;
  /// when the packet was held; the maximum hold time is measured from the
  /// oldest one
  std::chrono::steady_clock::time_point t_enq{};

  uint8_t* data() { return buf.get() + HEADROOM; }
  const uint8_t* data() const { return buf.get() + HEADROOM; }
};

/// Held packets of one session, oldest first. A deque, so that detaching the
/// whole FIFO is a swap.
using dl_fifo = std::deque<dl_packet>;

/// What the end of a Session Modification decided for a session's held
/// packets: the verdict, and the entries end_session_modification() moved out
/// (for every verdict, not only FLUSH). The caller replays them (FLUSH) or
/// frees them, after the response is sent.
struct dl_flush_result {
  dl_verdict verdict = dl_verdict::keep;
  dl_fifo removed;
};

/// The DL buffer's bounds. All are finite (the configuration rejects 0),
/// because the SMF may never end buffering while the DN keeps sending to an
/// idle UE. Held packets leave at the end of a Session Modification (FLUSH,
/// DISCARD, or KEEP for the packets whose rule no longer buffers), when the
/// session is deleted, or when the maximum hold time expires. The member
/// defaults serve the self-tests: in the UPF, dl_buffer_limits_from_config()
/// (pfcp_switch.cpp) sets the bounds from the configuration and max_pkt_len
/// from the DL receive buffer, to which a static_assert also pins the default.
struct dl_buffer_limits {
  bool enabled                   = false;
  uint32_t max_pkts_per_session  = 64;
  uint64_t max_bytes_per_session = 128 * 1024;
  uint32_t max_pkts_total        = 16384;
  uint64_t max_bytes_total       = 32ULL * 1024 * 1024;
  /// PFCP_SWITCH_RECV_BUFFER_SIZE - ROOM_FOR_GTPV1U_G_PDU: nothing longer can
  /// come off the DL path, and the replay has to fit back into it.
  uint32_t max_pkt_len = 2048 - 64;
};

/// Counters. Invariants, once no enqueue or replay is in flight:
///   stored  = flushed + discarded + expired + held
///   flushed = replay_sent + replay_dropped + replay_rebuffered
struct dl_buffer_stats {
  uint64_t stored            = 0;
  uint64_t stale_dropped     = 0;
  uint64_t tombstone_dropped = 0;
  uint64_t no_record_dropped = 0;
  uint64_t overflow_dropped  = 0;
  uint64_t flushed           = 0;
  uint64_t discarded         = 0;
  uint64_t expired           = 0;
  uint64_t replay_sent       = 0;
  uint64_t replay_dropped    = 0;
  uint64_t replay_rebuffered = 0;
  uint64_t held              = 0;  ///< gauge

  bool operator==(const dl_buffer_stats& o) const {
    return stored == o.stored && stale_dropped == o.stale_dropped &&
           tombstone_dropped == o.tombstone_dropped &&
           no_record_dropped == o.no_record_dropped &&
           overflow_dropped == o.overflow_dropped && flushed == o.flushed &&
           discarded == o.discarded && expired == o.expired &&
           replay_sent == o.replay_sent && replay_dropped == o.replay_dropped &&
           replay_rebuffered == o.replay_rebuffered && held == o.held;
  }
  bool operator!=(const dl_buffer_stats& o) const { return !(*this == o); }
};

/// One session's FIFO discarded by expire(), with each PDR ID its packets were
/// held for, once, so that the caller can re-arm those PDRs' notification
/// latches.
struct dl_expired {
  uint64_t seid    = 0;
  size_t discarded = 0;
  std::vector<uint16_t> pdr_ids;
};

/// A Downlink Data Report that could not be queued: the notification latch of
/// its PDR stays set until the tick takes this mark.
struct dl_report_retry {
  uint64_t seid   = 0;
  uint16_t pdr_id = 0;
};

/// A reservation taken by prepare_enqueue(). Holds no pointer into the store:
/// the record may be tombstoned, or erased, before commit. Public so that
/// test_dl_flush.cpp can interleave the phases with detach/tombstone/gc;
/// production uses enqueue() only.
struct dl_reservation {
  bool ok          = false;
  uint64_t seid    = 0;
  uint64_t uid     = 0;
  uint32_t charged = 0;
  explicit operator bool() const { return ok; }
};

/**
 * @brief DL packets held while the UE is idle, per UP SEID (paging).
 *
 * Header-only and free of pfcp types and logging, like qos_mbr.hpp, so that
 * the self-check needs nothing but a compiler.
 *
 * Held packets live outside pfcp_session because the session's rules are
 * copy-on-write and edited on TASK_UPF_APP while the DL threads and the AF_XDP
 * consumer enqueue, and late packets must still be refused after the session
 * object is gone.
 *
 * This store applies no BAR IE: its bounds are the UPF's own (dl_buffer_* in
 * the configuration). The simple switch applies no BAR IE at all. On the eBPF
 * datapath, a BAR's Suggested Buffering Packets Count is applied earlier, by
 * the XDP BAR program, before capture.
 *
 * A buffering period runs from the moment a FAR of the session gets Apply
 * Action BUFF until that FAR leaves BUFF or is removed, or the session is
 * deleted. Expiry of the maximum hold time does not end it.
 *
 * Each session has a record: `buffering_uids` (the rule_uids that may buffer
 * now), a FIFO, its share of the bounds, and a state (Active or Tombstone). A
 * packet is admitted only if its uid is in `buffering_uids`. After
 * establishment, only end_session_modification() changes `buffering_uids` of a
 * live record; tombstone() clears it.
 *
 * Threads: enqueue() and mark_report_failed() run on the DL threads, and on
 * TASK_UPF_APP while it replays held packets; enqueue() also runs on the
 * AF_XDP consumer thread. prepare_enqueue(), commit_enqueue() and
 * cancel_enqueue() run inside enqueue(). tombstone() runs on TASK_UPF_APP, and
 * on TASK_UPF_N4 when the heartbeat gives up on the association. The other
 * non-const members (publish(), end_session_modification(), expire(), gc(),
 * take_report_retries() and note_replay()) run on TASK_UPF_APP. Records are
 * split over 16 shards, each with its own mutex.
 *
 * No packet buffer is allocated, copied or freed while a shard lock is held,
 * so that a DL thread never waits on another thread's malloc, free or copy of
 * up to 2 KB. (Small container nodes, such as a deque chunk, a vector or a map
 * node, may still be allocated or freed under the lock.)
 *
 * Admission has three phases: (1) reserve the bounds under the shard lock
 * (prepare_enqueue), (2) copy the packet without the lock (make_packet), (3)
 * link it under the lock after checking the record again (commit_enqueue). A
 * refused packet is counted once. Bytes are charged by allocated size.
 *
 * With `enabled` false the records do nothing. The report retry marks also
 * work with buffering off, so a Downlink Data Report that could not be queued
 * is retried whether or not buffering is on.
 */
class dl_packet_buffer {
 public:
  using clock = std::chrono::steady_clock;

  static constexpr size_t SHARDS = 16;

  explicit dl_packet_buffer(const dl_buffer_limits& l = dl_buffer_limits())
      : limits_(l) {}

  dl_packet_buffer(const dl_packet_buffer&)            = delete;
  dl_packet_buffer& operator=(const dl_packet_buffer&) = delete;

  bool enabled() const { return limits_.enabled; }
  const dl_buffer_limits& limits() const { return limits_; }

  /// What a packet of `len` payload bytes is charged.
  static uint32_t charge_of(size_t len) {
    return static_cast<uint32_t>(len + dl_packet::HEADROOM + sizeof(dl_packet));
  }

  //----------------------------------------------------------------------------
  /**
   * @brief Establishment: create the session's DL buffer record, with the uids
   * that buffer now (normally none). On an existing Active record it replaces
   * `buffering_uids`. No-op when buffering is off or on a tombstone.
   */
  void publish(uint64_t seid, const std::vector<uint64_t>& uids) {
    if (!limits_.enabled) return;
    shard& sh = shard_of(seid);
    std::lock_guard<std::mutex> lk(sh.mu);
    auto it = sh.records.find(seid);
    if (it == sh.records.end()) {
      record& r        = sh.records[seid];
      r.buffering_uids = uids;
      return;
    }
    if (it->second.tombstone) return;
    it->second.buffering_uids = uids;
  }

  //----------------------------------------------------------------------------
  /**
   * @brief Hold a copy of a DL packet. DL threads; never throws or logs
   * (an allocation failure is a refusal, counted as overflow_dropped).
   * @return true when the packet was linked.
   */
  bool enqueue(
      uint64_t seid, uint64_t uid, uint16_t pdr_id, const uint8_t* pkt,
      size_t len, clock::time_point now = clock::now()) {
    dl_reservation r = prepare_enqueue(seid, uid, len);
    if (!r) return false;
    dl_packet p;
    if (!make_packet(p, r, pdr_id, pkt, len, now)) {
      cancel_enqueue(r);
      return false;
    }
    return commit_enqueue(r, std::move(p));
  }

  //----------------------------------------------------------------------------
  /// Admission phase 1: reserve room for one packet of `len` bytes, or refuse
  /// it and count why. Public so that test_dl_flush.cpp can interleave the
  /// phases with detach/tombstone/gc; production uses enqueue() only.
  dl_reservation prepare_enqueue(uint64_t seid, uint64_t uid, size_t len) {
    dl_reservation res;
    if (!limits_.enabled) return res;
    if (len == 0 || len > limits_.max_pkt_len) {
      bump(overflow_dropped_);
      return res;
    }
    const uint32_t charge = charge_of(len);
    // Fast path: a full store refuses without the lock or an allocation.
    if (g_pkts_.load(std::memory_order_relaxed) >= limits_.max_pkts_total ||
        g_bytes_.load(std::memory_order_relaxed) + charge >
            limits_.max_bytes_total) {
      bump(overflow_dropped_);
      return res;
    }
    shard& sh = shard_of(seid);
    {
      std::lock_guard<std::mutex> lk(sh.mu);
      auto it = sh.records.find(seid);
      if (it == sh.records.end()) {
        bump(no_record_dropped_);
        return res;
      }
      record& r = it->second;
      if (r.tombstone) {
        bump(tombstone_dropped_);
        return res;
      }
      if (!r.admits(uid)) {
        bump(stale_dropped_);
        return res;
      }
      if (r.reserved_pkts + 1 > limits_.max_pkts_per_session ||
          r.reserved_bytes + charge > limits_.max_bytes_per_session ||
          !reserve_global(charge)) {
        bump(overflow_dropped_);
        return res;
      }
      r.reserved_pkts += 1;
      r.reserved_bytes += charge;
    }
    res.ok      = true;
    res.seid    = seid;
    res.uid     = uid;
    res.charged = charge;
    return res;
  }

  //----------------------------------------------------------------------------
  /**
   * @brief Admission phase 3: link the copied packet, or refuse it and give
   * the reservation back.
   *
   * Public so that test_dl_flush.cpp can interleave the phases with
   * detach/tombstone/gc; production uses enqueue() only.
   * @return true when linked (`p` is moved from). On false, `p` is untouched
   * and the caller frees it, outside every lock.
   */
  bool commit_enqueue(dl_reservation& res, dl_packet&& p) {
    if (!res) return false;
    res.ok    = false;
    shard& sh = shard_of(res.seid);
    std::lock_guard<std::mutex> lk(sh.mu);
    auto it = sh.records.find(res.seid);
    if (it == sh.records.end()) {
      // gc() erased the record, and its per-session share with it.
      release_global(1, res.charged);
      bump(no_record_dropped_);
      return false;
    }
    record& r = it->second;
    if (r.tombstone || !r.admits(res.uid)) {
      release_session(r, 1, res.charged);
      release_global(1, res.charged);
      bump(r.tombstone ? tombstone_dropped_ : stale_dropped_);
      return false;
    }
    try {
      // A new deque chunk can throw; push_back then leaves `p` and the FIFO
      // untouched, so the refusal is the same as any other (OOM only).
      r.fifo.push_back(std::move(p));
    } catch (...) {
      release_session(r, 1, res.charged);
      release_global(1, res.charged);
      bump(overflow_dropped_);
      return false;
    }
    bump(stored_);
    bump(held_);
    return true;
  }

  //----------------------------------------------------------------------------
  /// Give back a reservation that will never be committed (allocation
  /// failure). Counted as overflow_dropped. Public like prepare_enqueue() and
  /// commit_enqueue(), but no self-test calls it; production uses enqueue()
  /// only.
  void cancel_enqueue(dl_reservation& res) {
    if (!res) return;
    res.ok    = false;
    shard& sh = shard_of(res.seid);
    {
      std::lock_guard<std::mutex> lk(sh.mu);
      auto it = sh.records.find(res.seid);
      if (it != sh.records.end()) release_session(it->second, 1, res.charged);
    }
    release_global(1, res.charged);
    bump(overflow_dropped_);
  }

  //----------------------------------------------------------------------------
  /**
   * @brief Replace the set of rule_uids that may buffer, and detach the held
   * packets that the verdict releases.
   *
   * Called once at the end of every accepted Session Modification, when DL
   * buffering is on. After establishment, this is the only place
   * `buffering_uids` changes for a live record; tombstone() clears it when the
   * session is deleted. FLUSH and DISCARD return the whole FIFO. KEEP returns
   * the entries whose rule_uid is no longer in `buffering_uids`, and keeps the
   * rest in order. The caller replays or frees what is returned. No-op on a
   * missing or tombstoned record.
   */
  dl_fifo end_session_modification(
      uint64_t seid, const std::vector<uint64_t>& buffering_uids,
      dl_verdict verdict) {
    dl_fifo out;
    if (!limits_.enabled) return out;
    shard& sh = shard_of(seid);
    {
      std::lock_guard<std::mutex> lk(sh.mu);
      auto it = sh.records.find(seid);
      if (it == sh.records.end() || it->second.tombstone) return out;
      record& r        = it->second;
      r.buffering_uids = buffering_uids;
      r.gen++;
      if (verdict == dl_verdict::keep) {
        dl_fifo kept;
        // An Update PDR gives the rule a new rule_uid, so its held packets are
        // no longer listed and are dropped here (docs/PAGING.md, Limitations).
        for (auto& e : r.fifo)
          (r.admits(e.rule_uid) ? kept : out).push_back(std::move(e));
        r.fifo.swap(kept);
      } else {
        out.swap(r.fifo);
      }
      release_entries(r, out);
    }
    add(verdict == dl_verdict::flush ? flushed_ : discarded_, out.size());
    return out;
  }

  //----------------------------------------------------------------------------
  /**
   * @brief Session end: discard the FIFO, refuse everything from now on, and
   * drop the session's report retry marks. The record is kept for one tick so
   * that late packets count as `tombstone_dropped` (session deleted), not
   * `no_record_dropped`; gc() then erases it. UP SEIDs are never reused, so a
   * tombstone never shadows a new session.
   * @return how many packets were discarded.
   */
  size_t tombstone(uint64_t seid, clock::time_point now = clock::now()) {
    dl_fifo dead;
    shard& sh = shard_of(seid);
    {
      std::lock_guard<std::mutex> lk(sh.mu);
      drop_marks_locked(sh, seid);
      if (!limits_.enabled) return 0;
      auto it = sh.records.find(seid);
      if (it == sh.records.end() || it->second.tombstone) return 0;
      record& r    = it->second;
      r.tombstone  = true;
      r.tomb_since = now;
      r.buffering_uids.clear();
      dead.swap(r.fifo);
      release_entries(r, dead);
    }
    add(discarded_, dead.size());
    return dead.size();
  }

  //----------------------------------------------------------------------------
  /**
   * @brief Maximum hold time: discard every FIFO whose oldest packet has
   * waited `max_hold_time` or longer. The buffering period goes on
   * (`buffering_uids` is unchanged). The caller re-arms the notification latch
   * of each returned PDR ID, so the next packet notifies the SMF again.
   */
  std::vector<dl_expired> expire(
      clock::time_point now, std::chrono::milliseconds max_hold_time) {
    std::vector<dl_expired> result;
    if (!limits_.enabled) return result;
    for (auto& sh : shards_) {
      std::vector<dl_fifo> dead;  // freed after the lock
      {
        std::lock_guard<std::mutex> lk(sh.mu);
        for (auto& kv : sh.records) {
          record& r = kv.second;
          if (r.tombstone || r.fifo.empty() ||
              now - r.fifo.front().t_enq < max_hold_time)
            continue;
          dl_expired x;
          x.seid = kv.first;
          for (const auto& e : r.fifo)
            if (std::find(x.pdr_ids.begin(), x.pdr_ids.end(), e.pdr_id) ==
                x.pdr_ids.end()) {
              x.pdr_ids.push_back(e.pdr_id);
            }
          dead.emplace_back();
          dead.back().swap(r.fifo);
          release_entries(r, dead.back());
          x.discarded = dead.back().size();
          add(expired_, x.discarded);
          result.push_back(std::move(x));
        }
      }
    }
    return result;
  }

  //----------------------------------------------------------------------------
  /// Erase the Tombstones older than `min_age`, with any marks left on them.
  /// @return how many records were erased.
  size_t gc(
      clock::time_point now,
      std::chrono::milliseconds min_age = std::chrono::milliseconds(1000)) {
    if (!limits_.enabled) return 0;
    size_t n = 0;
    for (auto& sh : shards_) {
      std::lock_guard<std::mutex> lk(sh.mu);
      for (auto it = sh.records.begin(); it != sh.records.end();) {
        if (it->second.tombstone && now - it->second.tomb_since >= min_age) {
          drop_marks_locked(sh, it->first);
          it = sh.records.erase(it);
          n++;
        } else {
          ++it;
        }
      }
    }
    return n;
  }

  //----------------------------------------------------------------------------
  /**
   * @brief A Downlink Data Report for (seid, pdr_id) could not be queued. The
   * notification latch stays set until the tick takes this mark. Ignored when
   * the session's record is a tombstone, or is missing while buffering is on
   * (session deleted, or not yet published). DL threads, and TASK_UPF_APP
   * during a replay; never throws.
   * @return false only when out of memory: the caller must then re-arm the
   * latch itself.
   */
  bool mark_report_failed(uint64_t seid, uint16_t pdr_id) {
    shard& sh = shard_of(seid);
    std::lock_guard<std::mutex> lk(sh.mu);
    auto it = sh.records.find(seid);
    const bool session_deleted =
        it != sh.records.end() ? it->second.tombstone : limits_.enabled;
    if (session_deleted) return true;
    for (const auto& m : sh.marks)
      if (m.seid == seid && m.pdr_id == pdr_id) return true;
    try {
      sh.marks.push_back(dl_report_retry{seid, pdr_id});
    } catch (...) {
      return false;  // push_back is strong: marks is unchanged
    }
    return true;
  }

  /// Drain every mark.
  std::vector<dl_report_retry> take_report_retries() {
    std::vector<dl_report_retry> out;
    for (auto& sh : shards_) {
      std::lock_guard<std::mutex> lk(sh.mu);
      out.insert(out.end(), sh.marks.begin(), sh.marks.end());
      sh.marks.clear();
    }
    return out;
  }

  //----------------------------------------------------------------------------
  /// Account for one flushed packet after its replay through the DL lookup.
  void note_replay(dl_outcome o) {
    switch (o) {
      case dl_outcome::sent:
        bump(replay_sent_);
        break;
      case dl_outcome::dropped:
        bump(replay_dropped_);
        break;
      case dl_outcome::rebuffered:
        bump(replay_rebuffered_);
        break;
    }
  }

  //----------------------------------------------------------------------------
  dl_buffer_stats stats() const {
    dl_buffer_stats s;
    s.stored            = stored_.load(std::memory_order_relaxed);
    s.stale_dropped     = stale_dropped_.load(std::memory_order_relaxed);
    s.tombstone_dropped = tombstone_dropped_.load(std::memory_order_relaxed);
    s.no_record_dropped = no_record_dropped_.load(std::memory_order_relaxed);
    s.overflow_dropped  = overflow_dropped_.load(std::memory_order_relaxed);
    s.flushed           = flushed_.load(std::memory_order_relaxed);
    s.discarded         = discarded_.load(std::memory_order_relaxed);
    s.expired           = expired_.load(std::memory_order_relaxed);
    s.replay_sent       = replay_sent_.load(std::memory_order_relaxed);
    s.replay_dropped    = replay_dropped_.load(std::memory_order_relaxed);
    s.replay_rebuffered = replay_rebuffered_.load(std::memory_order_relaxed);
    s.held              = held_.load(std::memory_order_relaxed);
    return s;
  }

  // ---- Diagnostics for the self-tests; no production caller ----

  /// Reserved packets / bytes, linked or still between prepare and commit.
  uint64_t total_pkts() const {
    return g_pkts_.load(std::memory_order_relaxed);
  }
  uint64_t total_bytes() const {
    return g_bytes_.load(std::memory_order_relaxed);
  }

  bool has_record(uint64_t seid) const {
    const shard& sh = shard_of(seid);
    std::lock_guard<std::mutex> lk(sh.mu);
    return sh.records.count(seid) != 0;
  }

  bool is_tombstone(uint64_t seid) const {
    return inspect(seid, [](const record& r) { return r.tombstone ? 1 : 0; });
  }
  uint64_t generation(uint64_t seid) const {
    return inspect(seid, [](const record& r) { return r.gen; });
  }
  uint64_t session_pkts(uint64_t seid) const {
    return inspect(seid, [](const record& r) { return r.reserved_pkts; });
  }
  uint64_t session_bytes(uint64_t seid) const {
    return inspect(seid, [](const record& r) { return r.reserved_bytes; });
  }
  size_t held_for(uint64_t seid) const {
    return inspect(seid, [](const record& r) { return r.fifo.size(); });
  }

 private:
  struct record {
    std::vector<uint64_t> buffering_uids;  ///< a handful at most: linear search
    uint64_t gen = 0;  ///< counts detaches; read only by the self-tests
    dl_fifo fifo;
    uint64_t reserved_pkts  = 0;  ///< reserved: linked + in flight
    uint64_t reserved_bytes = 0;
    bool tombstone          = false;
    clock::time_point tomb_since{};

    bool admits(uint64_t uid) const {
      return std::find(buffering_uids.begin(), buffering_uids.end(), uid) !=
             buffering_uids.end();
    }
  };

  struct shard {
    mutable std::mutex mu;
    std::unordered_map<uint64_t, record> records;
    /// Report retry marks. Beside the records, not in them, so they work with
    /// buffering off. A few at most: linear dedup.
    std::vector<dl_report_retry> marks;
  };

  static constexpr uint64_t FIBONACCI_HASH_MULTIPLIER = 0x9E3779B97F4A7C15ULL;
  static_assert(SHARDS == 16, "the shard hash keeps log2(SHARDS) = 4 bits");

  /// Shards stop DL threads that buffer for different sessions from
  /// serialising on one lock.
  shard& shard_of(uint64_t seid) {
    return shards_[(seid * FIBONACCI_HASH_MULTIPLIER) >> 60];
  }
  const shard& shard_of(uint64_t seid) const {
    return shards_[(seid * FIBONACCI_HASH_MULTIPLIER) >> 60];
  }

  template<typename F>
  uint64_t inspect(uint64_t seid, F f) const {
    const shard& sh = shard_of(seid);
    std::lock_guard<std::mutex> lk(sh.mu);
    auto it = sh.records.find(seid);
    return it == sh.records.end() ? 0 : static_cast<uint64_t>(f(it->second));
  }

  static void drop_marks_locked(shard& sh, uint64_t seid) {
    sh.marks.erase(
        std::remove_if(
            sh.marks.begin(), sh.marks.end(),
            [seid](const dl_report_retry& m) { return m.seid == seid; }),
        sh.marks.end());
  }

  static bool make_packet(
      dl_packet& p, const dl_reservation& r, uint16_t pdr_id,
      const uint8_t* pkt, size_t len, clock::time_point now) {
    p.buf.reset(new (std::nothrow) uint8_t[dl_packet::HEADROOM + len]);
    if (!p.buf) return false;
    std::memcpy(p.data(), pkt, len);
    p.len      = static_cast<uint32_t>(len);
    p.charged  = r.charged;
    p.rule_uid = r.uid;
    p.pdr_id   = pdr_id;
    p.t_enq    = now;
    return true;
  }

  /// Both bounds or neither; never over either, even transiently.
  bool reserve_global(uint32_t charge) {
    uint64_t n = g_pkts_.load(std::memory_order_relaxed);
    do {
      if (n + 1 > limits_.max_pkts_total) return false;
    } while (
        !g_pkts_.compare_exchange_weak(n, n + 1, std::memory_order_relaxed));
    uint64_t b = g_bytes_.load(std::memory_order_relaxed);
    do {
      if (b + charge > limits_.max_bytes_total) {
        g_pkts_.fetch_sub(1, std::memory_order_relaxed);
        return false;
      }
    } while (!g_bytes_.compare_exchange_weak(
        b, b + charge, std::memory_order_relaxed));
    return true;
  }

  void release_global(uint64_t pkts, uint64_t bytes) {
    g_pkts_.fetch_sub(pkts, std::memory_order_relaxed);
    g_bytes_.fetch_sub(bytes, std::memory_order_relaxed);
  }

  static void release_session(record& r, uint64_t pkts, uint64_t bytes) {
    r.reserved_pkts -= pkts;
    r.reserved_bytes -= bytes;
  }

  /// Entries leaving a record: give back both shares and the held gauge.
  void release_entries(record& r, const dl_fifo& gone) {
    if (gone.empty()) return;
    uint64_t bytes = 0;
    for (const auto& e : gone) bytes += e.charged;
    release_session(r, gone.size(), bytes);
    release_global(gone.size(), bytes);
    held_.fetch_sub(gone.size(), std::memory_order_relaxed);
  }

  static void bump(std::atomic<uint64_t>& c) {
    c.fetch_add(1, std::memory_order_relaxed);
  }
  static void add(std::atomic<uint64_t>& c, uint64_t n) {
    if (n) c.fetch_add(n, std::memory_order_relaxed);
  }

  const dl_buffer_limits limits_;
  std::array<shard, SHARDS> shards_;

  std::atomic<uint64_t> g_pkts_{0};
  std::atomic<uint64_t> g_bytes_{0};

  std::atomic<uint64_t> stored_{0};
  std::atomic<uint64_t> stale_dropped_{0};
  std::atomic<uint64_t> tombstone_dropped_{0};
  std::atomic<uint64_t> no_record_dropped_{0};
  std::atomic<uint64_t> overflow_dropped_{0};
  std::atomic<uint64_t> flushed_{0};
  std::atomic<uint64_t> discarded_{0};
  std::atomic<uint64_t> expired_{0};
  std::atomic<uint64_t> replay_sent_{0};
  std::atomic<uint64_t> replay_dropped_{0};
  std::atomic<uint64_t> replay_rebuffered_{0};
  std::atomic<uint64_t> held_{0};
};

}  // namespace oai::upf

#endif
