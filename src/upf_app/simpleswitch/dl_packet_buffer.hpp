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
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>

namespace oai::upf {

/**
 * @brief What to do with a session's held DL packets at the end of an N4
 * Session Modification.
 *
 * FLUSH replays them through the DL lookup against the new rules, DISCARD
 * frees them, KEEP leaves those still owned by a buffering rule in place.
 */
enum class dl_verdict { keep, flush, discard };

inline const char* to_string(dl_verdict v) {
  switch (v) {
    case dl_verdict::flush:
      return "FLUSH";
    case dl_verdict::discard:
      return "DISCARD";
    default:
      return "KEEP";
  }
}

/// What one Session Modification did to the buffering rules. Each flag is set
/// only after the matching removal or update has succeeded.
struct dl_signals {
  bool buff_pdr_removed = false;  ///< Remove PDR of a PDR whose FAR buffers
  bool buff_far_removed = false;  ///< Remove FAR of a buffering FAR
  bool buff_to_forw     = false;  ///< Update FAR BUFF -> FORW (§5.2.4.2)
};

/**
 * @brief The verdict, as a pure function of the signals.
 *
 * - FLUSH: the buffering FAR was removed or turned into FORW (TS 29.244
 *   §5.2.4.2). This wins over Remove PDR, which the OAI SMF sends in the
 *   same message.
 * - DISCARD: the buffering PDR was removed, or no buffering FAR is left.
 * - KEEP: anything else.
 */
inline dl_verdict verdict_of(const dl_signals& s, bool buff_far_left) {
  if (s.buff_far_removed || s.buff_to_forw) return dl_verdict::flush;
  if (s.buff_pdr_removed || !buff_far_left) return dl_verdict::discard;
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
  uint32_t len      = 0;
  uint32_t charged  = 0;  ///< bytes charged against the bounds
  uint64_t rule_uid = 0;
  uint16_t pdr_id   = 0;
  std::chrono::steady_clock::time_point t_enq{};

  uint8_t* data() { return buf.get() + HEADROOM; }
  const uint8_t* data() const { return buf.get() + HEADROOM; }
};

/// A detached FIFO. A deque, so that FLUSH and DISCARD move it out in O(1).
using dl_fifo = std::deque<dl_packet>;

/// What the end of a Session Modification decided for a session's held
/// packets: the verdict and the entries detach_and_rearm() moved out. The
/// caller replays them (FLUSH) or frees them, after the response is sent.
struct dl_flush_result {
  dl_verdict verdict = dl_verdict::keep;
  dl_fifo removed;
};

/// The bounds. Finite on purpose: the SMF never says stop, and the DN can
/// flood an idle UE, so memory is only ever released by these and by T_guard
/// (the maximum hold time, default_buffering_duration_ms).
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

/// One session's FIFO discarded by expire(): the uids its packets were held
/// under, so the caller can re-arm those PDRs' DL notification latch, and
/// beside each its PDR ID (pdr_ids[i] goes with uids[i]).
///
/// The PDR ID finds the rule when an Update PDR replaced the uid but left it
/// unlisted in `valid` (a Session Modification Request that was rejected
/// after it had already applied the update), exactly as for a dl_ddn_mark.
/// Without it that latch would stay held until the next Session Modification.
struct dl_expired {
  uint64_t seid    = 0;
  size_t discarded = 0;
  std::vector<uint64_t> uids;
  std::vector<uint16_t> pdr_ids;
};

/// A DL Data Report that could not be handed to TASK_UPF_N4: the latch of
/// the rule it was sent for stays held until the tick takes this mark. The
/// PDR ID is kept beside the uid because an Update PDR gives the rule a fresh
/// uid (copy-on-write) that inherits the held latch: the uid alone would then
/// find nothing to re-arm (see find_rearm_target()).
struct dl_ddn_mark {
  uint64_t seid   = 0;
  uint64_t uid    = 0;
  uint16_t pdr_id = 0;
};

/**
 * @brief The rule whose DL notification latch a re-arm addresses.
 *
 * The rule with `uid`; if none, the rule with `pdr_id` (an Update PDR gives
 * the copy a new uid, but it keeps the latch). Templated so that the
 * self-check needs no pfcp types.
 * @return the rule, or nullptr.
 */
template<typename Rule>
Rule* find_rearm_target(
    const std::vector<std::shared_ptr<Rule>>& rules,
    const std::optional<uint64_t>& uid, const std::optional<uint16_t>& pdr_id) {
  if (uid)
    for (const auto& r : rules)
      if (r && r->rule_uid == *uid) return r.get();
  // PDR IDs are unique within a session, so this never reaches an unrelated
  // rule. It can reach a rule re-created under the same PDR ID (Remove +
  // Create) that has already latched for its own report: at worst one
  // duplicate, harmless DL Data Report (the SMF starts paging only once).
  if (pdr_id)
    for (const auto& r : rules)
      if (r && r->pdr_id.rule_id == *pdr_id) return r.get();
  return nullptr;
}

/// A reservation taken by prepare_enqueue(). Holds no pointer into the store:
/// the record may be tombstoned, or erased, before commit.
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
 * Each session has a record: `valid` (the rule_uids that may buffer now), a
 * FIFO, its share of the bounds, and a state (Active or Tombstone). A packet
 * is admitted only if its uid is in `valid`. Only detach_and_rearm() changes
 * `valid` after establishment.
 *
 * Threads: enqueue() runs on the DL threads, tombstone() also on
 * TASK_UPF_N4, the rest on TASK_UPF_APP. Records are split over 16 shards,
 * each with its own mutex. Never hold a shard lock while logging,
 * allocating or freeing a packet.
 *
 * Admission: reserve the bounds under the lock, copy the packet without it,
 * then link it under the lock after checking the record again. A refused
 * packet is counted once. Bytes are charged by allocated size.
 *
 * With `enabled` false the records do nothing. The DDN (Downlink Data
 * Notification) retry marks still work, so a failed DL Data Report is
 * retried either way.
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
   * @brief Establishment: create the record with the uids that buffer now
   * (normally none). Updates `valid` on an Active record; no-op on a
   * Tombstone.
   */
  void publish(uint64_t seid, const std::vector<uint64_t>& uids) {
    if (!limits_.enabled) return;
    shard& sh = shard_of(seid);
    std::lock_guard<std::mutex> lk(sh.mu);
    auto it = sh.records.find(seid);
    if (it == sh.records.end()) {
      record& r = sh.records[seid];
      r.valid   = uids;
      return;
    }
    if (it->second.tombstone) return;
    it->second.valid = uids;
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
  /// Steps 1 and 2 of admission. A refusal is counted here.
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
      if (!r.lists(uid)) {
        bump(stale_dropped_);
        return res;
      }
      if (r.pkts + 1 > limits_.max_pkts_per_session ||
          r.bytes + charge > limits_.max_bytes_per_session ||
          !reserve_global(charge)) {
        bump(overflow_dropped_);
        return res;
      }
      r.pkts += 1;
      r.bytes += charge;
    }
    res.ok      = true;
    res.seid    = seid;
    res.uid     = uid;
    res.charged = charge;
    return res;
  }

  //----------------------------------------------------------------------------
  /**
   * @brief Step 4 of admission: link `p`, or refuse and roll back.
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
    if (r.tombstone || !r.lists(res.uid)) {
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
  /// failure). Counted as overflow_dropped.
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
   * @brief End of a Session Modification: the single reopen point.
   *
   * Sets `valid = new_valid`. FLUSH and DISCARD return the whole FIFO. KEEP
   * returns only the entries whose uid left `valid`, and keeps the rest in
   * order. The caller replays or frees what is returned. No-op on a missing
   * or Tombstone record.
   */
  dl_fifo detach_and_rearm(
      uint64_t seid, const std::vector<uint64_t>& new_valid, dl_verdict v) {
    dl_fifo out;
    if (!limits_.enabled) return out;
    shard& sh = shard_of(seid);
    {
      std::lock_guard<std::mutex> lk(sh.mu);
      auto it = sh.records.find(seid);
      if (it == sh.records.end() || it->second.tombstone) return out;
      record& r = it->second;
      r.valid   = new_valid;
      r.gen++;
      if (v == dl_verdict::keep) {
        dl_fifo kept;
        for (auto& e : r.fifo)
          (r.lists(e.rule_uid) ? kept : out).push_back(std::move(e));
        r.fifo.swap(kept);
      } else {
        out.swap(r.fifo);
      }
      release_entries(r, out);
    }
    add(v == dl_verdict::flush ? flushed_ : discarded_, out.size());
    return out;
  }

  //----------------------------------------------------------------------------
  /**
   * @brief Session end: discard the FIFO, refuse everything from now on, and
   * drop the session's DDN retry marks. The record is erased by gc() once it
   * is older than one tick, far longer than any DL read section, so a late
   * packet finds a Tombstone and not a missing record. UP SEIDs are never
   * reused, so a Tombstone never shadows a new session.
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
      r.valid.clear();
      dead.swap(r.fifo);
      release_entries(r, dead);
    }
    add(discarded_, dead.size());
    return dead.size();
  }

  //----------------------------------------------------------------------------
  /**
   * @brief T_guard: discard every FIFO whose oldest packet has waited
   * `t_guard` or longer. The episode stays open (`valid` is unchanged); the
   * caller re-arms the notification latch on the returned uids (by PDR ID
   * when the uid is gone), so the next packet notifies the SMF again.
   */
  std::vector<dl_expired> expire(
      clock::time_point now, std::chrono::milliseconds t_guard) {
    std::vector<dl_expired> result;
    if (!limits_.enabled) return result;
    for (auto& sh : shards_) {
      std::vector<dl_fifo> dead;  // freed after the lock
      {
        std::lock_guard<std::mutex> lk(sh.mu);
        for (auto& kv : sh.records) {
          record& r = kv.second;
          if (r.tombstone || r.fifo.empty() ||
              now - r.fifo.front().t_enq < t_guard)
            continue;
          dl_expired x;
          x.seid = kv.first;
          for (const auto& e : r.fifo)
            if (std::find(x.uids.begin(), x.uids.end(), e.rule_uid) ==
                x.uids.end()) {
              x.uids.push_back(e.rule_uid);
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
   * @brief A DL Data Report for (seid, uid) could not be enqueued. The latch
   * stays held until the tick takes this mark. Ignored if the session is
   * gone. DL threads; never throws.
   * @return false if the mark could not be stored (out of memory); the
   * caller must then release the latch itself.
   */
  bool mark_ddn_failed(uint64_t seid, uint64_t uid, uint16_t pdr_id) {
    shard& sh = shard_of(seid);
    std::lock_guard<std::mutex> lk(sh.mu);
    auto it = sh.records.find(seid);
    if (it != sh.records.end() ? it->second.tombstone : limits_.enabled)
      return true;
    for (const auto& m : sh.marks)
      if (m.seid == seid && m.uid == uid) return true;
    try {
      sh.marks.push_back(dl_ddn_mark{seid, uid, pdr_id});
    } catch (...) {
      return false;  // push_back is strong: marks is unchanged
    }
    return true;
  }

  /// Drain every mark.
  std::vector<dl_ddn_mark> take_ddn_retries() {
    std::vector<dl_ddn_mark> out;
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

  // ---- Diagnostics and tests -----------------------------------------------

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
    return inspect(seid, [](const record& r) { return r.pkts; });
  }
  uint64_t session_bytes(uint64_t seid) const {
    return inspect(seid, [](const record& r) { return r.bytes; });
  }
  size_t held_for(uint64_t seid) const {
    return inspect(seid, [](const record& r) { return r.fifo.size(); });
  }

 private:
  struct record {
    std::vector<uint64_t> valid;  ///< a handful at most: linear search
    uint64_t gen = 0;
    dl_fifo fifo;
    uint64_t pkts  = 0;  ///< reserved: linked + in flight
    uint64_t bytes = 0;
    bool tombstone = false;
    clock::time_point tomb_since{};

    bool lists(uint64_t uid) const {
      return std::find(valid.begin(), valid.end(), uid) != valid.end();
    }
  };

  struct shard {
    mutable std::mutex mu;
    std::unordered_map<uint64_t, record> records;
    /// DDN retry marks. Beside the records, not in them, so they work with
    /// buffering off. A few at most: linear dedup.
    std::vector<dl_ddn_mark> marks;
  };

  shard& shard_of(uint64_t seid) {
    return shards_[(seid * 0x9E3779B97F4A7C15ULL) >> 60];
  }
  const shard& shard_of(uint64_t seid) const {
    return shards_[(seid * 0x9E3779B97F4A7C15ULL) >> 60];
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
            [seid](const dl_ddn_mark& m) { return m.seid == seid; }),
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
    r.pkts -= pkts;
    r.bytes -= bytes;
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
