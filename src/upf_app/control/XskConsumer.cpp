/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "XskConsumer.hpp"

#include <bpf/bpf.h>
#include <dirent.h>
#include <poll.h>
#include <sys/mman.h>
#include <xdp/xsk.h>

#include <cerrno>
#include <cinttypes>
#include <cstring>
#include <string>

#include "fmt/format.h"
#include "logger.hpp"
#include "pfcp_switch.hpp"
#include "wrappers/BPFMap.hpp"
#include "xsk_frame.hpp"

extern oai::upf::app::pfcp_switch* pfcp_switch_inst;

namespace oai {
namespace upf {
namespace app {

/// One N6 RX queue: its UMEM, its socket and the rings they share. libxdp
/// keeps pointers to the rings, so a Queue never moves (held by unique_ptr).
struct XskConsumer::Queue {
  uint32_t id               = 0;
  void* area                = nullptr;  ///< UMEM memory (mmap)
  size_t area_len           = 0;
  struct xsk_umem* umem     = nullptr;
  struct xsk_socket* xsk    = nullptr;
  struct xsk_ring_prod fill = {};
  /// Completion ring: the UMEM requires one; never used (RX only).
  struct xsk_ring_cons comp = {};
  struct xsk_ring_cons rx   = {};
  bool in_map               = false;  ///< published in xskmap[id]
};

//------------------------------------------------------------------------------
XskConsumer::XskConsumer() {}

//------------------------------------------------------------------------------
XskConsumer::~XskConsumer() {
  Stop();
}

//------------------------------------------------------------------------------
bool XskConsumer::IsRunning() const {
  return running_.load(std::memory_order_acquire);
}

//------------------------------------------------------------------------------
XskConsumer::Counters XskConsumer::GetCounters() const {
  Counters c;
  c.received      = received_.load(std::memory_order_relaxed);
  c.malformed     = malformed_.load(std::memory_order_relaxed);
  c.not_buffering = not_buffering_.load(std::memory_order_relaxed);
  c.stored        = stored_.load(std::memory_order_relaxed);
  c.refused       = refused_.load(std::memory_order_relaxed);
  return c;
}

//------------------------------------------------------------------------------
int XskConsumer::CountRxQueues(const std::string& ifname) {
  const std::string path = "/sys/class/net/" + ifname + "/queues";
  DIR* d                 = opendir(path.c_str());
  if (!d) return -1;
  int n = 0;
  while (struct dirent* e = readdir(d)) {
    if (strncmp(e->d_name, "rx-", 3) == 0) ++n;
  }
  closedir(d);
  return n;
}

//------------------------------------------------------------------------------
bool XskConsumer::Start(
    const Config& cfg, const std::shared_ptr<BPFMap>& xskmap) {
  if (IsRunning()) {
    Logger::upf_app().warn("DL buffer AF_XDP consumer is already running");
    return true;
  }
  // A thread that ended on a poll error leaves a joinable thread and its
  // sockets behind; reap them before starting over.
  Stop();

  std::string why;
  const int map_fd = xskmap ? xskmap->GetFd() : -1;
  const int n      = CountRxQueues(cfg.ifname);
  const uint64_t per_queue =
      (uint64_t) cfg.frames_per_queue * (uint64_t) cfg.frame_size;

  if (map_fd < 0) {
    why = "xskmap is not loaded";
  } else if (n <= 0) {
    why = fmt::format(
        "cannot read the RX queues of {} (/sys/class/net/{}/queues)",
        cfg.ifname, cfg.ifname);
  } else if ((uint32_t) n > cfg.max_queues) {
    why = fmt::format(
        "{} has {} RX queues, xskmap has {} slots", cfg.ifname, n,
        cfg.max_queues);
  } else if (per_queue * (uint64_t) n > cfg.umem_max_bytes) {
    why = fmt::format(
        "{} RX queues x {} frames x {} B = {} MiB exceeds "
        "xsk_umem_max_mib_total ({} MiB)",
        n, cfg.frames_per_queue, cfg.frame_size,
        (per_queue * (uint64_t) n) >> 20, cfg.umem_max_bytes >> 20);
  }

  // One UMEM per queue, each ring sized to hold every frame: the fill ring
  // can then always take back what the RX ring hands over.
  for (int i = 0; why.empty() && i < n; ++i) {
    auto q      = std::make_unique<Queue>();
    q->id       = (uint32_t) i;
    q->area_len = (size_t) per_queue;
    void* area  = mmap(
        nullptr, q->area_len, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (area == MAP_FAILED) {
      why = fmt::format(
          "queue {}: mmap of {} B failed: {}", i, q->area_len, strerror(errno));
      break;
    }
    q->area = area;
    queues_.push_back(std::move(q));
    Queue& cur = *queues_.back();

    struct xsk_umem_config ucfg = {};
    ucfg.fill_size              = cfg.frames_per_queue;
    ucfg.comp_size              = cfg.frames_per_queue;
    ucfg.frame_size             = cfg.frame_size;
    ucfg.frame_headroom         = 0;
    ucfg.flags                  = 0;
    int ret                     = xsk_umem__create(
        &cur.umem, cur.area, cur.area_len, &cur.fill, &cur.comp, &ucfg);
    if (ret != 0) {
      cur.umem = nullptr;
      why = fmt::format("queue {}: xsk_umem__create: {}", i, strerror(-ret));
      break;
    }

    struct xsk_socket_config scfg = {};
    scfg.rx_size                  = cfg.frames_per_queue;
    scfg.tx_size                  = 0;
    // Never let libxdp load or replace an XDP program: the UPF's own program
    // is attached already and redirects through the UPF's own xskmap.
    scfg.libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD;
    scfg.xdp_flags    = 0;
    // Always copy mode, native or SKB attach: capture is a slow path, while
    // with no flag the kernel binds zero-copy on a capable NIC, which puts
    // the whole N6 queue (forwarded DL too) on this UMEM and this thread.
    scfg.bind_flags = XDP_COPY;
    ret             = xsk_socket__create(
        &cur.xsk, cfg.ifname.c_str(), cur.id, cur.umem, &cur.rx, nullptr,
        &scfg);
    if (ret != 0) {
      cur.xsk = nullptr;
      why     = fmt::format(
          "queue {}: xsk_socket__create on {}: {}", i, cfg.ifname,
          strerror(-ret));
      break;
    }

    // Post every frame to the fill ring, so the kernel can use all of them.
    uint32_t idx = 0;
    if (xsk_ring_prod__reserve(&cur.fill, cfg.frames_per_queue, &idx) !=
        cfg.frames_per_queue) {
      why = fmt::format("queue {}: cannot post the fill ring", i);
      break;
    }
    for (uint32_t f = 0; f < cfg.frames_per_queue; ++f)
      *xsk_ring_prod__fill_addr(&cur.fill, idx + f) =
          (uint64_t) f * cfg.frame_size;
    xsk_ring_prod__submit(&cur.fill, cfg.frames_per_queue);
  }

  // Publish only once every queue has a socket: all or nothing.
  for (auto& q : queues_) {
    if (!why.empty()) break;
    uint32_t key = q->id;
    int fd       = xsk_socket__fd(q->xsk);
    if (bpf_map_update_elem(map_fd, &key, &fd, BPF_ANY) != 0) {
      why = fmt::format(
          "queue {}: xskmap update failed: {}", q->id, strerror(errno));
      break;
    }
    q->in_map = true;
  }

  if (!why.empty()) {
    xskmap_ = xskmap;  // so ReleaseAll() can remove what was published
    ReleaseAll();
    Logger::upf_app().error(
        "DL buffer AF_XDP capture disabled, buffered packets are dropped: %s",
        why.c_str());
    return false;
  }

  xskmap_     = xskmap;
  frame_size_ = cfg.frame_size;
  running_.store(true, std::memory_order_release);
  try {
    poll_thread_ = std::thread(&XskConsumer::PollLoop, this);
  } catch (const std::exception& e) {
    running_.store(false, std::memory_order_release);
    ReleaseAll();
    Logger::upf_app().error(
        "DL buffer AF_XDP capture disabled, buffered packets are dropped: "
        "cannot start the thread: %s",
        e.what());
    return false;
  }

  Logger::upf_app().info(
      "DL buffer AF_XDP capture on %s: %d RX queue(s), %u frames x %u B each "
      "(%s)",
      cfg.ifname.c_str(), n, cfg.frames_per_queue, cfg.frame_size,
      cfg.skb_mode ? "copy, SKB mode" : "copy, native mode");
  return true;
}

//------------------------------------------------------------------------------
void XskConsumer::Stop() noexcept {
  running_.store(false, std::memory_order_release);
  // Not running_: the poll thread clears it itself when poll() fails, and the
  // counters are still worth logging then. Queues exist only after Start().
  const bool started = !queues_.empty();

  if (poll_thread_.joinable()) {
    // Same guard as BarDdnConsumer::Stop(): joining self throws, and inside a
    // signal handler (SIGSEGV on this thread) that would be std::terminate.
    if (poll_thread_.get_id() == std::this_thread::get_id()) {
      poll_thread_.detach();
    } else {
      try {
        poll_thread_.join();
      } catch (...) {
      }
    }
  }

  ReleaseAll();

  if (started) {
    const Counters c = GetCounters();
    Logger::upf_app().info(
        "DL buffer AF_XDP capture stopped (received=%" PRIu64
        ", malformed=%" PRIu64 ", not_buffering=%" PRIu64 ", stored=%" PRIu64
        ", refused=%" PRIu64 ")",
        c.received, c.malformed, c.not_buffering, c.stored, c.refused);
  }
}

//------------------------------------------------------------------------------
void XskConsumer::Unpublish() noexcept {
  const int map_fd = xskmap_ ? xskmap_->GetFd() : -1;
  for (auto& q : queues_) {
    if (q->in_map && map_fd >= 0) {
      uint32_t key = q->id;
      (void) bpf_map_delete_elem(map_fd, &key);
    }
    q->in_map = false;
  }
}

//------------------------------------------------------------------------------
void XskConsumer::ReleaseAll() noexcept {
  // Unpublish first so no packet is redirected to a closing socket, then the
  // socket, then its UMEM (which refuses to go while a socket uses it), then
  // the memory under it.
  Unpublish();
  for (auto& q : queues_) {
    if (q->xsk) xsk_socket__delete(q->xsk);
    q->xsk = nullptr;
    if (q->umem) (void) xsk_umem__delete(q->umem);
    q->umem = nullptr;
    if (q->area) munmap(q->area, q->area_len);
    q->area = nullptr;
  }
  queues_.clear();
  xskmap_.reset();
}

//------------------------------------------------------------------------------
void XskConsumer::PollLoop() {
  Logger::upf_app().debug("DL buffer AF_XDP poll thread running");

  std::vector<struct pollfd> fds(queues_.size());
  for (size_t i = 0; i < queues_.size(); ++i) {
    fds[i].fd     = xsk_socket__fd(queues_[i]->xsk);
    fds[i].events = POLLIN;
  }

  while (running_.load(std::memory_order_acquire)) {
    const int ret = poll(fds.data(), fds.size(), kPollTimeoutMs);
    std::string why;
    if (ret < 0) {
      if (errno == EINTR) continue;
      why = fmt::format("poll failed: {}", strerror(errno));
    }
    for (size_t i = 0; why.empty() && ret > 0 && i < fds.size(); ++i) {
      // An AF_XDP socket does not report these today; treat them as fatal
      // anyway.
      if (fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
        why = fmt::format(
            "queue {}: poll revents 0x{:x}", queues_[i]->id,
            (unsigned) fds[i].revents);
      } else if (fds[i].revents & POLLIN) {
        DrainQueue(*queues_[i]);
      }
    }
    if (!why.empty()) {
      Logger::upf_app().error(
          "DL buffer AF_XDP %s -- capture stops, buffered packets are dropped "
          "from here on",
          why.c_str());
      // The sockets and UMEMs stay until Stop() has joined this thread; only
      // the map entries go now, so XDP falls back to its XDP_DROP at once.
      Unpublish();
      running_.store(false, std::memory_order_release);
      break;
    }
  }

  Logger::upf_app().debug("DL buffer AF_XDP poll thread exited");
}

//------------------------------------------------------------------------------
void XskConsumer::DrainQueue(Queue& q) {
  uint32_t rx_idx  = 0;
  const uint32_t n = xsk_ring_cons__peek(&q.rx, kRxBatch, &rx_idx);
  if (n == 0) return;

  // The fill ring has a slot for every frame of the UMEM, so it always has
  // room for the ones the RX ring just handed over.
  uint32_t fill_idx = 0;
  while (xsk_ring_prod__reserve(&q.fill, n, &fill_idx) != n) {
    if (!running_.load(std::memory_order_acquire)) return;
    std::this_thread::yield();
  }

  const uint64_t frame_mask = ~((uint64_t) frame_size_ - 1);
  for (uint32_t i = 0; i < n; ++i) {
    const struct xdp_desc* d = xsk_ring_cons__rx_desc(&q.rx, rx_idx + i);
    const uint8_t* frame =
        static_cast<const uint8_t*>(xsk_umem__get_data(q.area, d->addr));
    // A descriptor the kernel wrote cannot point outside its frame, but the
    // copy below trusts the length, so bound it anyway.
    const uint64_t offset = d->addr & ~frame_mask;
    const uint32_t len    = (offset + d->len <= frame_size_) ? d->len : 0;
    HandleFrame(frame, len);
    *xsk_ring_prod__fill_addr(&q.fill, fill_idx + i) = d->addr & frame_mask;
  }
  xsk_ring_prod__submit(&q.fill, n);
  xsk_ring_cons__release(&q.rx, n);
}

//------------------------------------------------------------------------------
void XskConsumer::HandleFrame(const uint8_t* frame, uint32_t len) {
  received_.fetch_add(1, std::memory_order_relaxed);

  const auto pkt = oai::upf::xsk_ipv4_span(frame, len);
  if (!pkt) {
    malformed_.fetch_add(1, std::memory_order_relaxed);
    return;
  }

  pfcp_switch* sw = pfcp_switch_inst;
  if (!sw) {
    not_buffering_.fetch_add(1, std::memory_order_relaxed);
    return;
  }
  // Lookup only: XDP already counted the packet and sent the DL Data Report.
  const auto m = sw->classify_dl_buffered(pkt.data, pkt.len);
  if (!m.is_buff) {
    not_buffering_.fetch_add(1, std::memory_order_relaxed);
    return;
  }
  if (sw->dl_buffer().enqueue(
          m.up_seid, m.rule_uid, m.pdr_id, pkt.data, pkt.len)) {
    stored_.fetch_add(1, std::memory_order_relaxed);
  } else {
    refused_.fetch_add(1, std::memory_order_relaxed);
  }
}

}  // namespace app
}  // namespace upf
}  // namespace oai
