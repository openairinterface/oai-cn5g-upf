#ifndef __PROGRAMLIFECYCLE_H__
#define __PROGRAMLIFECYCLE_H__

#include <atomic>
#include <bpf/libbpf.h>     //bpf function
#include <functional>       // rlimit
#include <linux/if_link.h>  // XDP flags
#include <map>
#include <net/if.h>        // if_nametoindex
#include <sstream>         //stringstream
#include <sys/resource.h>  // rlimit
#include <vector>
#include <Configuration.h>
#include "logger.hpp"

/**
 * @brief Program states.
 */
enum ProgramState {
  IDLE,
  OPENED,
  LOADED,
  ATTACHED,
  LINKED,
  DESTROYED,
};

template<class BPFSkeletonType>
class ProgramLifeCycle {
 public:
  /**
   * @brief Construct a new Program Life Cycle object.
   *
   * @param openFunc
   * @param loadFunc
   * @param attachFunc
   * @param destroyFunc
   */
  ProgramLifeCycle(
      std::function<BPFSkeletonType*()> openFunc,
      std::function<int(BPFSkeletonType*)> loadFunc,
      std::function<int(BPFSkeletonType*)> attachFunc,
      std::function<void(BPFSkeletonType*)> destroyFunc);
  /**
   * @brief Destroy the Program Life Cycle object.
   *
   */
  virtual ~ProgramLifeCycle();
  /**
   * @brief Open the BPF program.
   *
   */
  BPFSkeletonType* open();
  /**
   * @brief Load the BPF program.
   *
   */
  void load();
  /**
   * @brief Attach the BPF program.
   *
   */
  void attach();
  /**
   * @brief Link The BPF XDP program.
   * The BPF program must be only link to one interface.
   * See RedHat presentation.
   *
   */
  void link(std::string sectionName, std::string interface);
  /**
   * @brief Destroy the BPF program.
   *
   */
  void destroy();
  /**
   * @brief Tear down all programs.
   *
   */
  void tearDown();
  /**
   * @brief Get BPF skeleton constructed.
   *
   * @return The skeleton reference. NULL if is not opened.
   */
  BPFSkeletonType* getBPFSkeleton() const;
  /**
   * @brief Get the State object.
   *
   * @return The BPF program state.
   */
  ProgramState getState() const;

 private:
  // Mutex for tearDown (async).
  std::mutex sTearDownMutex;
  // The program state.
  std::atomic<ProgramState> mState;
  std::map<std::string, std::vector<uint32_t>> mSectionLinkInterfacesMap;
  std::function<BPFSkeletonType*()> mOpenFunc;
  std::function<int(BPFSkeletonType*)> mLoadFunc;
  std::function<int(BPFSkeletonType*)> mAttachFunc;
  std::function<void(BPFSkeletonType*)> mDestroyFunc;
  BPFSkeletonType* mpSkeleton;
  uint32_t mFlags;
};

template<class BPFSkeletonType>
ProgramLifeCycle<BPFSkeletonType>::ProgramLifeCycle(
    std::function<BPFSkeletonType*()> openFunc,
    std::function<int(BPFSkeletonType*)> loadFunc,
    std::function<int(BPFSkeletonType*)> attachFunc,
    std::function<void(BPFSkeletonType*)> destroyFunc)
    : mOpenFunc(openFunc),
      mLoadFunc(loadFunc),
      mAttachFunc(attachFunc),
      mDestroyFunc(destroyFunc),
      mpSkeleton(NULL) {
  // Check if the XDP is driver or skb mode.
  mFlags = Configuration::sIsSocketBufferEnabled ?
               XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE :
               XDP_FLAGS_UPDATE_IF_NOEXIST;
}

template<class BPFSkeletonType>
ProgramLifeCycle<BPFSkeletonType>::~ProgramLifeCycle() {
  // if(mpSkeleton != NULL) {
  //   delete mpSkeleton;
  // }
}

template<class BPFSkeletonType>
BPFSkeletonType* ProgramLifeCycle<BPFSkeletonType>::open() {
  struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
  if (setrlimit(RLIMIT_MEMLOCK, &r)) {
    perror("setrlimit(RLIMIT_MEMLOCK)");
    throw std::runtime_error("Cannot change bpf limit program");
  }

  mpSkeleton = mOpenFunc();
  if (!mpSkeleton) mDestroyFunc(mpSkeleton);

  mState = OPENED;

  return mpSkeleton;
}

template<class BPFSkeletonType>
void ProgramLifeCycle<BPFSkeletonType>::load() {
  // Load BPF programs identified in skeleton.
  // We do not need to pass the path of the .o (object), due to encapsulation
  // made by bpftool in skeleton object.
  if (int err = mLoadFunc(mpSkeleton)) {
    mDestroyFunc(mpSkeleton);
    std::stringstream errMsg;
    errMsg << "Cannot load program - error" << err;
    throw std::runtime_error(errMsg.str());
  }
  mState = LOADED;
}

template<class BPFSkeletonType>
void ProgramLifeCycle<BPFSkeletonType>::attach() {
  // Attach is not support by XDP programs.
  // This call does not do anything.
  if (int err = mAttachFunc(mpSkeleton)) {
    mDestroyFunc(mpSkeleton);
    std::stringstream errMsg;
    errMsg << "Cannot attach program - error" << err;
    throw std::runtime_error(errMsg.str());
  }
  mState = ATTACHED;
}

template<class BPFSkeletonType>
void ProgramLifeCycle<BPFSkeletonType>::link(
    std::string sectionName, std::string interface) {
  struct bpf_program* prog;
  auto ifIndex = if_nametoindex(interface.c_str());
  int fd;
  std::string section;

  // TODO: Remove hardcoded.
  if (!ifIndex) {
    perror("if_nametoindex");
    Logger::upf_app().error("Interface %s not found", interface.c_str());
    throw std::runtime_error("Interface not found!");
  }

  bpf_object__for_each_program(prog, mpSkeleton->obj) {
    // Get section name.
    section = std::string(bpf_program__section_name(prog));
    if (section == sectionName) {
      // Get programs FD from skeleton object.
      fd = bpf_program__fd(prog);
      // Link program (fd) to the interface.
      if (bpf_set_link_xdp_fd(ifIndex, fd, mFlags) < 0) {
        Logger::upf_app().error(
            "BPF program %s link set XDP failed", sectionName.c_str());
        tearDown();
        throw std::runtime_error("BPF program link set XDP failed");
      }

      // Add a new entry if doesnt exist.
      // Cc, push back the ney entry to the exist.
      auto it = mSectionLinkInterfacesMap.find(section);
      if (it == mSectionLinkInterfacesMap.end()) {
        std::vector<uint32_t> linkVector;
        linkVector.push_back(ifIndex);
        mSectionLinkInterfacesMap[sectionName] = linkVector;
      } else {
        it->second.push_back(ifIndex);
      }

      // Update the global link state.
      mState = LINKED;
      Logger::upf_app().info(
          "BPF program %s hooked in %s XDP interface", sectionName.c_str(),
          interface.c_str());
      return;
    };
  }
  Logger::upf_app().error("Section %s not found", sectionName.c_str());
  throw std::runtime_error("Section not found");
}

template<class BPFSkeletonType>
void ProgramLifeCycle<BPFSkeletonType>::tearDown() {
  std::lock_guard<std::mutex> lock(sTearDownMutex);
  struct bpf_program* prog;
  std::string section;

  if (mState != ProgramState::IDLE) {
    if (mState == LINKED) {
      Logger::upf_app().debug("There are some programs in LINKED state");
      bpf_object__for_each_program(prog, mpSkeleton->obj) {
        // Get section name.
        section = std::string(bpf_program__section_name(prog));
        // Find the section.
        auto it = mSectionLinkInterfacesMap.find(section);
        if (it == mSectionLinkInterfacesMap.end()) {
          Logger::upf_app().debug(
              "BPF program %s are not link to any interface", section.c_str());
          continue;
        }
        // For each link in this section, do unlink.
        for (auto linkEntry : it->second) {
          Logger::upf_app().debug(
              "BPF program %s is in a HOOKED state", section.c_str());
          if (bpf_set_link_xdp_fd(linkEntry, -1, mFlags)) {
            Logger::upf_app().error(
                "BPF program %s cannot unlink the %d interface",
                section.c_str(), linkEntry);
            throw std::runtime_error("BPF program cannot unlink");
          };
          Logger::upf_app().info(
              "BPF program %s unlink to %d interface", section.c_str(),
              linkEntry);
        }
      }
    } else {
      Logger::upf_app().debug("There are not any program in LINKED state.");
    }
    destroy();
  } else {
    Logger::upf_app().debug("Programs is in IDLE state. TearDown skipped");
  }
}

template<class BPFSkeletonType>
void ProgramLifeCycle<BPFSkeletonType>::destroy() {
  // Destroy program.
  if (mState != IDLE) {
    mDestroyFunc(mpSkeleton);
  }
  // TODO: Check if it is necessary delete sessionManager here.
  mState = IDLE;
}

template<class BPFSkeletonType>
BPFSkeletonType* ProgramLifeCycle<BPFSkeletonType>::getBPFSkeleton() const {
  return mpSkeleton;
}

template<class BPFSkeletonType>
ProgramState ProgramLifeCycle<BPFSkeletonType>::getState() const {
  return mState;
}

#endif  // __PROGRAMLIFECYCLE_H__
