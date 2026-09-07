/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef UPF_MAP_HPP_SEEN
#define UPF_MAP_HPP_SEEN

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

#include "upf_rcu.hpp"

namespace oai::upf {

/**
 * @brief Bounded lock-free lookup table for the datapath.
 *
 * The three maps it backs are all bounded and keyed on an integer -- TEID, UE
 * IPv4, SEID -- so a fixed-size table sized once at start-up is all that is
 * needed, and it avoids pulling a general-purpose concurrent container (and
 * its dependency chain) into the build.
 *
 * Shape: open addressing with linear probing, sized to a power of two. Readers
 * are wait-free and take no locks; writers (the PFCP control plane, which is
 * orders of magnitude slower) serialise on a mutex. A slot is one of
 *   nullptr    never used -- a probe that reaches one ends the search
 *   TOMBSTONE  erased -- probing continues past it
 *   node*      live
 *
 * find() deliberately returns a POINTER to the stored shared_ptr rather than a
 * copy: the datapath needs the object, not ownership of it, and copying cost
 * two atomic RMWs per lookup. Lifetime is guaranteed by the rcu_domain -- the
 * caller must hold an rcu_guard for as long as it uses the result, and erase()
 * defers the node's destruction until every such reader has finished.
 */
template<typename K, typename V>
class upf_map {
 public:
  upf_map(size_t capacity, rcu_domain& rcu) : rcu_(rcu) {
    // Keep the load factor under 0.5 so probe chains stay short.
    size_t n = 16;
    while (n < capacity * 2) n <<= 1;
    mask_  = n - 1;
    slots_ = std::vector<std::atomic<node*>>(n);
    for (auto& s : slots_) s.store(nullptr, std::memory_order_relaxed);
  }

  ~upf_map() {
    for (auto& s : slots_) {
      node* p = s.load(std::memory_order_relaxed);
      if (p && p != tombstone()) delete p;
    }
  }

  upf_map(const upf_map&) = delete;
  upf_map& operator=(const upf_map&) = delete;

  /**
   * @brief Look up @p key. Wait-free.
   * @return pointer to the stored value, or nullptr. Valid only while the
   *         caller's rcu_guard is alive.
   */
  const std::shared_ptr<V>* find(const K& key) const noexcept {
    size_t i = index_of(key);
    for (size_t probe = 0; probe <= mask_; probe++) {
      node* p = slots_[i].load(std::memory_order_acquire);
      if (p == nullptr) return nullptr;  // never used: key cannot be beyond
      if (p != tombstone() && p->key == key) return &p->val;
      i = (i + 1) & mask_;
    }
    return nullptr;
  }

  /** @brief Insert or replace. Writer side. */
  bool insert(const K& key, std::shared_ptr<V> val) {
    std::lock_guard<std::mutex> lk(write_mu_);
    size_t i     = index_of(key);
    ssize_t free = -1;
    for (size_t probe = 0; probe <= mask_; probe++) {
      node* p = slots_[i].load(std::memory_order_relaxed);
      if (p == nullptr) {
        if (free < 0) free = (ssize_t) i;
        break;
      }
      if (p == tombstone()) {
        if (free < 0) free = (ssize_t) i;
      } else if (p->key == key) {
        // Replace: publish the new node, then retire the old one.
        node* fresh = new node{key, std::move(val)};
        slots_[i].store(fresh, std::memory_order_release);
        rcu_.retire([p]() { delete p; });
        return true;
      }
      i = (i + 1) & mask_;
    }
    if (free < 0) return false;  // table full
    node* fresh = new node{key, std::move(val)};
    // Release: the node is fully constructed before any reader can see it.
    slots_[(size_t) free].store(fresh, std::memory_order_release);
    count_.fetch_add(1, std::memory_order_relaxed);
    return true;
  }

  /** @brief Remove @p key. Writer side. The node is freed once readers leave.
   */
  bool erase(const K& key) {
    std::lock_guard<std::mutex> lk(write_mu_);
    size_t i = index_of(key);
    for (size_t probe = 0; probe <= mask_; probe++) {
      node* p = slots_[i].load(std::memory_order_relaxed);
      if (p == nullptr) return false;
      if (p != tombstone() && p->key == key) {
        // Unlink FIRST, retire second: that ordering is what makes the
        // reclamation safe (see rcu_domain).
        slots_[i].store(tombstone(), std::memory_order_release);
        count_.fetch_sub(1, std::memory_order_relaxed);
        rcu_.retire([p]() { delete p; });
        return true;
      }
      i = (i + 1) & mask_;
    }
    return false;
  }

  /**
   * @brief Visit every live entry as f(const K&, const std::shared_ptr<V>&).
   * @note Writer side: holds the write lock, so it excludes insert/erase.
   */
  template<typename F>
  void for_each(F&& f) const {
    std::lock_guard<std::mutex> lk(write_mu_);
    for (auto& s : slots_) {
      node* p = s.load(std::memory_order_acquire);
      if (p && p != tombstone()) f(p->key, p->val);
    }
  }

  size_t size() const { return count_.load(std::memory_order_relaxed); }

 private:
  struct node {
    K key;                   // immutable once published
    std::shared_ptr<V> val;  // owns the value
  };

  static node* tombstone() noexcept {
    return reinterpret_cast<node*>(static_cast<uintptr_t>(1));
  }

  size_t index_of(const K& key) const noexcept {
    // Fibonacci hashing: cheap, and it spreads the low-entropy keys we have
    // (sequential TEIDs, consecutive UE addresses) across the whole table.
    uint64_t h = static_cast<uint64_t>(key) * 0x9E3779B97F4A7C15ULL;
    return (size_t) (h >> 32) & mask_;
  }

  mutable std::vector<std::atomic<node*>> slots_;
  size_t mask_ = 0;
  std::atomic<size_t> count_{0};
  mutable std::mutex write_mu_;
  rcu_domain& rcu_;
};

}  // namespace oai::upf

#endif /* UPF_MAP_HPP_SEEN */
