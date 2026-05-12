/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef PROGRAM_LIFE_CYCLE_HPP_
#define PROGRAM_LIFE_CYCLE_HPP_

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <errno.h>
#include <string.h>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include "logger.hpp"

// TC handle and priority defaults
#define INGRESS_HANDLE 0x1
#define INGRESS_PRIORITY 0xC02F
#define INGRESS_BROADCAST_PRIORITY 0x0003
#define EGRESS_HANDLE 0x10000
#define EGRESS_PRIORITY 0xC02F
#define EGRESS_BROADCAST_PRIORITY 0x0003

/**
 * @enum ProgramState
 * @brief BPF program lifecycle states
 */
enum ProgramState {
  IDLE                = 0,  ///< Program not initialized
  OPENED              = 1,  ///< Skeleton opened
  LOADED              = 2,  ///< Program loaded into kernel
  ATTACHED            = 3,  ///< Program attached to hooks
  LINKED              = 4,  ///< XDP linked to interface
  ATTACHED_TO_INGRESS = 5,  ///< TC attached to ingress
  ATTACHED_TO_EGRESS  = 6   ///< TC attached to egress
};

/**
 * @class ProgramLifeCycle
 * @brief Manages the complete lifecycle of a BPF/eBPF program
 *
 * This template class wraps libbpf skeleton operations and provides:
 * - Lazy initialization (open on first use)
 * - XDP program attachment to network interfaces
 * - TC (Traffic Control) program attachment for QoS
 * - Automatic cleanup via RAII pattern
 * - Error handling and logging
 *
 * Lifecycle Stages:
 * 1. **Open**: Create skeleton, configure maps/rodata
 * 2. **Load**: Load BPF bytecode into kernel
 * 3. **Attach**: Attach to hooks (XDP, TC, etc.)
 * 4. **Link**: Bind XDP/TC programs to specific interfaces
 * 5. **TearDown**: Detach and destroy
 *
 * Thread Safety: tearDown() is thread-safe via mutex
 *
 * @tparam T BPF skeleton type (must match libbpf generated skeleton)
 */
template<typename T>
class ProgramLifeCycle {
 public:
  /**
   * @brief Type alias for open function pointer
   *
   * Function signature: T* open_fn()
   * Should call the skeleton's __open() function and configure maps/rodata
   */
  using OpenFunction = std::function<T*()>;

  /**
   * @brief Type alias for load function pointer
   *
   * Function signature: int load_fn(T* skeleton)
   * Should call the skeleton's __load() function
   */
  using LoadFunction = std::function<int(T*)>;

  /**
   * @brief Type alias for attach function pointer
   *
   * Function signature: int attach_fn(T* skeleton)
   * Should call the skeleton's __attach() function
   */
  using AttachFunction = std::function<int(T*)>;

  /**
   * @brief Type alias for destroy function pointer
   *
   * Function signature: void destroy_fn(T* skeleton)
   * Should call the skeleton's __destroy() function
   */
  using DestroyFunction = std::function<void(T*)>;

  /**
   * @brief Constructor - stores function pointers, no allocation
   *
   * @param name       Human-readable program name used in all log output
   *                   (e.g. "N3EntryProgram", "QERProgram").
   * @param open_fn    Function to open/create the BPF skeleton
   * @param load_fn    Function to load BPF program into kernel
   * @param attach_fn  Function to attach BPF program to hooks
   * @param destroy_fn Function to destroy/cleanup BPF program
   *
   * @note Actual initialization is lazy - happens on first open() call
   */
  ProgramLifeCycle(
      OpenFunction open_fn, LoadFunction load_fn, AttachFunction attach_fn,
      DestroyFunction destroy_fn, const std::string& name = "BPFProgram")
      : name_(name),
        open_fn_(open_fn),
        load_fn_(load_fn),
        attach_fn_(attach_fn),
        destroy_fn_(destroy_fn),
        skeleton_(nullptr),
        state_(IDLE),
        xdp_flags_(
            XDP_FLAGS_UPDATE_IF_NOEXIST) {  // No explicit mode = auto fallback
    //  Logger::upf_app().info("XDP mode: Auto (native with SKB fallback)");
  }

  /**
   * @brief Destructor - ensures cleanup if not explicitly torn down
   *
   * Automatically calls tearDown() if the program is still active.
   * Best practice: call tearDown() explicitly for controlled cleanup.
   */
  ~ProgramLifeCycle() {
    if (skeleton_ && state_ != IDLE) {
      Logger::upf_app().debug(
          "[%s] Auto-cleanup of BPF program in destructor", name_.c_str());
      tearDown();
    }
  }

  /**
   * @brief Check if interface is using native XDP
   * @param interface Interface name
   * @return true if native XDP, false if SKB or not found
   */
  bool IsNativeXdp(const std::string& interface) const {
    auto it = interface_native_xdp_.find(interface);
    return (it != interface_native_xdp_.end()) ? it->second : false;
  }

  /**
   * @brief Get XDP mode string for display
   * @param interface Interface name
   * @return "Native (Hardware)" or "SKB (Software)"
   */
  std::string GetXdpModeString(const std::string& interface) const {
    return IsNativeXdp(interface) ? "Native (Hardware)" : "SKB (Software)";
  }

  /**
   * @brief Open BPF skeleton and configure maps/rodata
   *
   * Creates the BPF skeleton object and allows configuration of:
   * - Map sizes (max_entries)
   * - Read-only data (.rodata section)
   * - Initial map values
   *
   * @return T* Pointer to the opened skeleton
   *
   * @throws std::runtime_error if open fails
   *
   * @note Only opens once - subsequent calls return cached skeleton
   * @note Must be called before load()
   */
  T* open() {
    if (!skeleton_) {
      skeleton_ = open_fn_();
      if (!skeleton_) {
        Logger::upf_app().error(
            "[%s] Failed to open BPF skeleton", name_.c_str());
        throw std::runtime_error("BPF skeleton open failed");
      }
      state_ = OPENED;
      Logger::upf_app().debug(
          "[%s] BPF skeleton opened successfully", name_.c_str());
    }
    return skeleton_;
  }

  /**
   * @brief Load BPF program into the kernel
   *
   * Performs BPF verification and loads the program bytecode into the kernel.
   * After loading:
   * - Program is verified by kernel BPF verifier
   * - Maps are created in kernel space
   * - Program is ready to be attached
   *
   * @throws std::runtime_error if load fails or skeleton not opened
   *
   * @note Must call open() before load()
   * @note Can only load once - subsequent calls are no-ops
   */
  void load() {
    if (!skeleton_) {
      Logger::upf_app().error(
          "[%s] Cannot load — skeleton not opened", name_.c_str());
      throw std::runtime_error("BPF skeleton not opened before load");
    }

    if (state_ >= LOADED) {
      Logger::upf_app().debug(
          "[%s] BPF program already loaded, skipping", name_.c_str());
      return;
    }

    int ret = load_fn_(skeleton_);
    if (ret < 0) {
      Logger::upf_app().error(
          "[%s] Failed to load BPF program: %d", name_.c_str(), ret);
      throw std::runtime_error("BPF program load failed");
    }

    state_ = LOADED;
    Logger::upf_app().debug(
        "[%s] BPF program  loaded successfully", name_.c_str());
  }

  /**
   * @brief Attach BPF program to kernel hooks
   *
   * Attaches the program to appropriate hooks based on program type:
   * - XDP: Attaches to network interface RX path
   * - TC: Attaches to qdisc egress/ingress
   * - Tracepoints: Attaches to kernel tracepoints
   *
   * @throws std::runtime_error if attach fails or program not loaded
   *
   * @note Must call load() before attach()
   * @note Can only attach once - subsequent calls are no-ops
   */
  void attach() {
    if (!skeleton_) {
      Logger::upf_app().error(
          "[%s] Cannot attach — skeleton not opened", name_.c_str());
      throw std::runtime_error("BPF skeleton not opened before attach");
    }

    if (state_ < LOADED) {
      Logger::upf_app().error(
          "[%s] Cannot attach — program not loaded", name_.c_str());
      throw std::runtime_error("BPF program not loaded before attach");
    }

    if (state_ >= ATTACHED) {
      Logger::upf_app().debug(
          "[%s] BPF program already attached, skipping", name_.c_str());
      return;
    }

    int ret = attach_fn_(skeleton_);
    if (ret < 0) {
      Logger::upf_app().error(
          "[%s] Failed to attach BPF program: %d", name_.c_str(), ret);
      throw std::runtime_error("BPF program attach failed");
    }

    state_ = ATTACHED;
    Logger::upf_app().debug(
        "[%s] BPF program attached successfully", name_.c_str());
  }

  /**
   * @brief Link XDP program section to a network interface
   *
   * Attaches a specific XDP program section to a network interface.
   * Used for multi-section XDP programs where different sections
   * handle different packet flows (e.g., uplink vs downlink).
   *
   * @param section_name Name of the BPF program section (e.g., "xdp_uplink")
   * @param interface Network interface name (e.g., "eth0", "n3")
   *
   * @throws std::runtime_error if linking fails
   *
   * Flags used:
   * - XDP_FLAGS_UPDATE_IF_NOEXIST: Update if program doesn't exist
   * - XDP_FLAGS_DRV_MODE: Use driver mode (fastest, hardware offload if
   * available)
   *
   * @note Must call load() before link()
   * @note Can link multiple sections to different interfaces
   *
   * @see XDP_FLAGS_DRV_MODE for driver mode vs SKB mode
   */
  void link(const char* section_name, const char* interface) {
    if (!skeleton_ || state_ < LOADED) {
      Logger::upf_app().error(
          "[%s] Cannot link — skeleton not opened or program not loaded",
          name_.c_str());
      throw std::runtime_error("BPF program not ready for linking");
    }

    int if_index = if_nametoindex(interface);
    if (if_index == 0) {
      Logger::upf_app().error(
          "[%s] Interface %s not found", name_.c_str(), interface);
      throw std::runtime_error("Network interface not found");
    }

    // Manually iterate through all programs to find the section
    struct bpf_program* prog        = nullptr;
    struct bpf_program* target_prog = nullptr;

    bpf_object__for_each_program(prog, skeleton_->obj) {
      const char* prog_name = bpf_program__name(prog);
      if (prog_name && strcmp(prog_name, section_name) == 0) {
        target_prog = prog;
        Logger::upf_app().debug(
            "[%s] Found BPF program section '%s'", name_.c_str(), section_name);
        break;
      }
    }

    if (!target_prog) {
      Logger::upf_app().error(
          "[%s] BPF program section '%s' not found", name_.c_str(),
          section_name);
      throw std::runtime_error("BPF program section not found");
    }

    int prog_fd = bpf_program__fd(target_prog);
    if (prog_fd < 0) {
      Logger::upf_app().error(
          "[%s] Failed to get FD for program section '%s'", name_.c_str(),
          section_name);
      throw std::runtime_error("Failed to get BPF program FD");
    }

    // Try attaching XDP program with smart fallback
    int ret              = -1;
    const char* mode_str = "unknown";

    // First try: Native mode (best performance)
    ret = bpf_xdp_attach(
        if_index, prog_fd, xdp_flags_ | XDP_FLAGS_DRV_MODE, nullptr);
    bool tried_native = (ret != 0);

    if (ret == 0) {
      mode_str                                      = "native (driver mode)";
      interface_native_xdp_[std::string(interface)] = true;
    } else if (ret == -EOPNOTSUPP || ret == -95) {
      // Native mode not supported, try SKB mode (software fallback)
      Logger::upf_app().warn(
          "[%s] Native XDP unsupported on %s (driver limitation), using SKB "
          "mode",
          name_.c_str(), interface);
      ret = bpf_xdp_attach(
          if_index, prog_fd, xdp_flags_ | XDP_FLAGS_SKB_MODE, nullptr);

      if (ret == 0) {
        mode_str                                      = "SKB (software mode)";
        interface_native_xdp_[std::string(interface)] = false;
      }
    }

    // If both attempts failed, throw error

    if (ret < 0) {
      Logger::upf_app().error(
          "[%s] Failed to attach XDP program '%s' to interface '%s': %d (%s)",
          name_.c_str(), section_name, interface, ret, strerror(-ret));
      throw std::runtime_error(
          "XDP attach failed in both native and SKB modes");
    }

    // Track linked interface
    std::string section_str(section_name);
    auto it = section_link_map_.find(section_str);
    if (it == section_link_map_.end()) {
      std::vector<uint32_t> link_vector;
      link_vector.push_back(if_index);
      section_link_map_[section_str] = link_vector;
    } else {
      it->second.push_back(if_index);
    }

    state_ = LINKED;
    Logger::upf_app().info(
        "[%s] XDP '%s' attached to %s (ifindex=%d, mode=%s%s)", name_.c_str(),
        section_name, interface, if_index, mode_str,
        tried_native ? ", fallback" : "");
  }

  /**
   * @brief Attach TC-BPF program to interface ingress
   *
   * Attaches a TC (Traffic Control) BPF program to the ingress qdisc
   * of a network interface. Used for QoS enforcement, traffic shaping,
   * and packet redirection on the receive path.
   *
   * @param section_name Name of the TC program section
   * @param interface Network interface name
   *
   * @throws std::runtime_error if attachment fails
   *
   * TC Hook Points:
   * - Ingress (this function): Packets entering the interface
   * - Egress: Packets leaving the interface (handled by qdisc)
   *
   * @note Must call load() before tcAttachIngress()
   * @note TC programs are managed via netlink and tc command
   *
   * @see tc(8) for Traffic Control documentation
   */
  void tcAttachIngress(const char* section_name, const char* interface) {
    if (!skeleton_ || state_ < LOADED) {
      Logger::upf_app().error(
          "[%s] Cannot attach TC — skeleton not opened or program not loaded",
          name_.c_str());
      throw std::runtime_error("BPF program not ready for TC attach");
    }

    int if_index = if_nametoindex(interface);
    if (if_index == 0) {
      Logger::upf_app().error(
          "[%s] Interface %s not found", name_.c_str(), interface);
      throw std::runtime_error("Network interface not found");
    }

    // Iterate through all programs to find the section by name
    // (tcAttachIngress)
    struct bpf_program* prog        = nullptr;
    struct bpf_program* target_prog = nullptr;

    bpf_object__for_each_program(prog, skeleton_->obj) {
      const char* prog_name = bpf_program__name(prog);
      if (prog_name && strcmp(prog_name, section_name) == 0) {
        target_prog = prog;
        Logger::upf_app().debug(
            "[%s] Found TC BPF program section '%s'", name_.c_str(),
            section_name);
        break;
      }
    }

    if (!target_prog) {
      Logger::upf_app().error(
          "[%s] TC BPF program section '%s' not found", name_.c_str(),
          section_name);
      throw std::runtime_error("TC BPF program section not found");
    }

    int prog_fd = bpf_program__fd(target_prog);
    if (prog_fd < 0) {
      Logger::upf_app().error(
          "[%s] Failed to get FD for TC program section '%s'", name_.c_str(),
          section_name);
      throw std::runtime_error("Failed to get TC BPF program FD");
    }

    // Create TC-BPF hook
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_INGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, attach_ingress);

    hook.ifindex           = if_index;
    attach_ingress.prog_fd = prog_fd;

    int err = bpf_tc_hook_create(&hook);
    if (err == -EEXIST) {
      Logger::upf_app().info(
          "Success: [%s] TC-BPF hook %s already exists for interface %s "
          "(Ignore: "
          "libbpf: Kernel error message))",
          name_.c_str(), section_name, interface);
    } else if (err) {
      Logger::upf_app().error(
          "[%s] Failed to create TC-BPF hook '%s' on %s (err=%d)",
          name_.c_str(), section_name, interface, err);
      throw std::runtime_error("TC hook creation failed");
    }

    // Attach the BPF program to ingress
    hook.attach_point       = BPF_TC_INGRESS;
    attach_ingress.flags    = BPF_TC_F_REPLACE;
    attach_ingress.handle   = INGRESS_HANDLE;
    attach_ingress.priority = INGRESS_PRIORITY;

    err = bpf_tc_attach(&hook, &attach_ingress);
    if (err) {
      Logger::upf_app().error(
          "[%s] Failed to attach ingress program '%s' to %s (err=%d)",
          name_.c_str(), section_name, interface, err);
      throw std::runtime_error("TC ingress attach failed");
    }

    // Track attached interface
    std::string section_str(section_name);
    auto it = section_link_map_.find(section_str);
    if (it == section_link_map_.end()) {
      std::vector<uint32_t> link_vector;
      link_vector.push_back(if_index);
      section_link_map_[section_str] = link_vector;
    } else {
      it->second.push_back(if_index);
    }

    state_ = ATTACHED_TO_INGRESS;
    Logger::upf_app().info(
        "[%s] TC-BPF '%s' attached to %s (ingress, ifindex=%d)", name_.c_str(),
        section_name, interface, if_index);
  }

  /**
   * @brief Attach TC-BPF program to interface egress
   *
   * Attaches a TC (Traffic Control) BPF program to the egress qdisc
   * of a network interface. Used for QoS enforcement, traffic shaping,
   * and packet redirection on the receive path.
   *
   * @param section_name Name of the TC program section
   * @param interface Network interface name
   *
   * @throws std::runtime_error if attachment fails
   *
   * TC Hook Points:
   * - Egress(this function): Packets leaving the interface (handled by qdisc)
   *
   * @note Must call load() before tcAttachEgress()
   * @note TC programs are managed via netlink and tc command
   *
   * @see tc(8) for Traffic Control documentation
   */
  void tcAttachEgress(const char* section_name, const char* interface) {
    if (!skeleton_ || state_ < LOADED) {
      Logger::upf_app().error(
          "[%s] Cannot attach TC — skeleton not opened or program not loaded",
          name_.c_str());
      throw std::runtime_error("BPF program not ready for TC attach");
    }

    int if_index = if_nametoindex(interface);
    if (if_index == 0) {
      Logger::upf_app().error(
          "[%s] Interface %s not found", name_.c_str(), interface);
      throw std::runtime_error("Network interface not found");
    }

    // Iterate through all programs to find the section by name (tcAttachEgress)
    struct bpf_program* prog        = nullptr;
    struct bpf_program* target_prog = nullptr;

    bpf_object__for_each_program(prog, skeleton_->obj) {
      const char* prog_name = bpf_program__name(prog);
      if (prog_name && strcmp(prog_name, section_name) == 0) {
        target_prog = prog;
        Logger::upf_app().debug(
            "[%s] Found TC BPF program section '%s'", name_.c_str(),
            section_name);
        break;
      }
    }

    if (!target_prog) {
      Logger::upf_app().error(
          "[%s] TC BPF program section '%s' not found", name_.c_str(),
          section_name);
      throw std::runtime_error("TC BPF program section not found");
    }

    int prog_fd = bpf_program__fd(target_prog);
    if (prog_fd < 0) {
      Logger::upf_app().error(
          "[%s] Failed to get FD for TC program section '%s'", name_.c_str(),
          section_name);
      throw std::runtime_error("Failed to get TC BPF program FD");
    }

    // TC-BPF hook and options (libbpf bpf_tc_hook/bpf_tc_opts)
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_EGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, attach_egress);

    hook.ifindex          = if_index;
    attach_egress.prog_fd = prog_fd;

    // Create TC-BPF hook
    int err = bpf_tc_hook_create(&hook);
    if (err == -EEXIST) {
      Logger::upf_app().info(
          "Success: [%s] TC-BPF hook %s already exists for interface %s "
          "(Ignore: "
          "libbpf: Kernel error message))",
          name_.c_str(), section_name, interface);
    } else if (err) {
      Logger::upf_app().error(
          "[%s] Failed to create TC-BPF hook '%s' on %s (err=%d)",
          name_.c_str(), section_name, interface, err);
      throw std::runtime_error("TC hook creation failed");
    }

    // Attach the BPF program to egress
    hook.attach_point      = BPF_TC_EGRESS;
    attach_egress.flags    = BPF_TC_F_REPLACE;
    attach_egress.handle   = EGRESS_HANDLE;
    attach_egress.priority = EGRESS_PRIORITY;

    err = bpf_tc_attach(&hook, &attach_egress);
    if (err) {
      Logger::upf_app().error(
          "[%s] Failed to attach egress program '%s' to %s (err=%d)",
          name_.c_str(), section_name, interface, err);
      throw std::runtime_error("TC egress attach failed");
    }

    // Track attached interface
    std::string section_str(section_name);
    auto it = section_link_map_.find(section_str);
    if (it == section_link_map_.end()) {
      std::vector<uint32_t> link_vector;
      link_vector.push_back(if_index);
      section_link_map_[section_str] = link_vector;
    } else {
      it->second.push_back(if_index);
    }

    state_ = ATTACHED_TO_EGRESS;
    Logger::upf_app().info(
        "[%s] TC-BPF '%s' attached to %s (egress, ifindex=%d)", name_.c_str(),
        section_name, interface, if_index);
  }

  /**
   * @brief Clean up and destroy BPF program
   *
   * Performs complete cleanup:
   * 1. Detaches program from hooks
   * 2. Unloads program from kernel
   * 3. Destroys skeleton and frees resources
   *
   * After tearDown():
   * - skeleton_ is set to nullptr
   * - Program cannot be reused
   * - Create a new instance for a new program
   *
   * @note Safe to call multiple times - subsequent calls are no-ops
   * @note Automatically called by destructor if not explicitly called
   */
  void tearDown() {
    std::lock_guard<std::mutex> lock(teardown_mutex_);

    if (state_ == IDLE) {
      Logger::upf_app().debug(
          "[%s] Already in IDLE state, tearDown skipped", name_.c_str());
      return;
    }

    // Unlink XDP programs if in LINKED state
    if (state_ == LINKED) {
      Logger::upf_app().debug(
          "[%s] Unlinking XDP programs from interfaces", name_.c_str());
      for (const auto& section_entry : section_link_map_) {
        const std::string& section_name         = section_entry.first;
        const std::vector<uint32_t>& interfaces = section_entry.second;

        for (uint32_t if_index : interfaces) {
          int ret = bpf_xdp_attach(if_index, -1, xdp_flags_, nullptr);
          if (ret) {
            Logger::upf_app().error(
                "[%s] Failed to unlink XDP '%s' from ifindex %d", name_.c_str(),
                section_entry.first.c_str(), if_index);
          } else {
            Logger::upf_app().info(
                "[%s] XDP '%s' unlinked from ifindex %d", name_.c_str(),
                section_entry.first.c_str(), if_index);
          }
        }
      }
      section_link_map_.clear();
    }

    // Destroy skeleton
    if (skeleton_) {
      Logger::upf_app().debug("[%s] Destroying BPF program", name_.c_str());
      destroy_fn_(skeleton_);
      skeleton_ = nullptr;
    }

    state_ = IDLE;
    Logger::upf_app().info(
        "[%s] BPF program torn down successfully", name_.c_str());
  }

  /**
   * @brief Get the BPF skeleton pointer
   *
   * Provides access to the underlying libbpf skeleton structure.
   * Useful for:
   * - Accessing BPF maps
   * - Retrieving program FDs
   * - Accessing .rodata/.bss sections
   *
   * @return T* Pointer to skeleton, or nullptr if not opened
   *
   * @warning Do not call destroy() on the returned pointer directly
   * @warning Use tearDown() instead to ensure proper cleanup
   */
  T* getBPFSkeleton() { return skeleton_; }

  /**
   * @brief Get current program state
   *
   * @return ProgramState Current lifecycle state
   */
  ProgramState getState() const { return state_; }

  // Delete copy constructor and assignment operator (non-copyable)
  ProgramLifeCycle(const ProgramLifeCycle&) = delete;
  ProgramLifeCycle& operator=(const ProgramLifeCycle&) = delete;

  // Allow move semantics for storing in containers
  ProgramLifeCycle(ProgramLifeCycle&&) = default;
  ProgramLifeCycle& operator=(ProgramLifeCycle&&) = default;

 private:
  std::string name_;            ///< Human-readable program name for logging
  OpenFunction open_fn_;        ///< Function to open BPF skeleton
  LoadFunction load_fn_;        ///< Function to load program into kernel
  AttachFunction attach_fn_;    ///< Function to attach program to hooks
  DestroyFunction destroy_fn_;  ///< Function to destroy and cleanup

  T* skeleton_;         ///< Pointer to BPF skeleton (nullptr if not opened)
  ProgramState state_;  ///< Current lifecycle state
  uint32_t xdp_flags_;  ///< XDP attachment flags (DRV_MODE or SKB_MODE)

  std::mutex teardown_mutex_;  ///< Mutex for thread-safe teardown
  std::map<std::string, std::vector<uint32_t>>
      section_link_map_;  ///< Track linked sections

  // Track XDP modes per interface
  std::map<std::string, bool>
      interface_native_xdp_;  // true = native, false = SKB
};

#endif  // PROGRAM_LIFE_CYCLE_HPP_
