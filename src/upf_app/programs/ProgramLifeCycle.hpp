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

#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <net/if.h>

#include <getopt.h>
#include <linux/in6.h>
#include <arpa/inet.h>
#include <linux/bpf.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define EGRESS_HANDLE 0x1
#define EGRESS_PRIORITY 0xC02F

#define INGRESS_HANDLE 0x1
#define INGRESS_PRIORITY 0xC02F

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
  ATTACHED_TO_INGRESS,
  ATTACHED_TO_EGRESS,
};

template<class BPFSkeletonType>
class ProgramLifeCycle {
 public:
  ProgramLifeCycle(
      std::function<BPFSkeletonType*()> openFunc,
      std::function<int(BPFSkeletonType*)> loadFunc,
      std::function<int(BPFSkeletonType*)> attachFunc,
      std::function<void(BPFSkeletonType*)> destroyFunc);

  virtual ~ProgramLifeCycle();

  BPFSkeletonType* open();
  void load();
  void attach();
  void link(std::string sectionName, std::string interface);
  void tcAttachIngress(std::string sectionName, std::string interface);
  void tcAttachEgress(std::string sectionName, std::string interface);
  void destroy();
  void tearDown();

  BPFSkeletonType* getBPFSkeleton() const;
  ProgramState getState() const;

 private:
  std::mutex sTearDownMutex;
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

//-------------------------------------------------------------------------------------------------------------
template<class BPFSkeletonType>
ProgramLifeCycle<BPFSkeletonType>::~ProgramLifeCycle() {
  // if(mpSkeleton != NULL) {
  //   delete mpSkeleton;
  // }
}

//-------------------------------------------------------------------------------------------------------------
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

//-------------------------------------------------------------------------------------------------------------
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

//-------------------------------------------------------------------------------------------------------------
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

//-------------------------------------------------------------------------------------------------------------
template<class BPFSkeletonType>
void ProgramLifeCycle<BPFSkeletonType>::link(
    std::string sectionName, std::string interface) {
  struct bpf_program* prog;
  auto ifIndex = if_nametoindex(interface.c_str());
  int fd;
  std::string prog_name;

  if (!ifIndex) {
    perror("if_nametoindex");
    Logger::upf_app().error("Interface %s not found", interface.c_str());
    throw std::runtime_error("Interface not found!");
  }

  bpf_object__for_each_program(prog, mpSkeleton->obj) {
    // Get section name.
    prog_name = std::string(bpf_program__name(prog));
    if (prog_name == sectionName) {
      // Get programs FD from skeleton object.
      fd = bpf_program__fd(prog);
      // Link program (fd) to the interface.
      if (bpf_xdp_attach(ifIndex, fd, mFlags, NULL) < 0) {
        Logger::upf_app().error(
            "BPF program %s link set XDP failed", sectionName.c_str());
        tearDown();
        throw std::runtime_error("BPF program link set XDP failed");
      }

      // Add a new entry if doesnt exist.
      // Cc, push back the ney entry to the exist.
      // auto it = mSectionLinkInterfacesMap.find(section);

      auto it = mSectionLinkInterfacesMap.find(prog_name);
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

//-------------------------------------------------------------------------------------------------------------
template<class BPFSkeletonType>
void ProgramLifeCycle<BPFSkeletonType>::tcAttachIngress(
    std::string sectionName, std::string interface) {
  int err = 0;
  int fd;
  struct bpf_program* prog = NULL;
  std::string prog_name;

  auto ifIndex = if_nametoindex(interface.c_str());

  if (!ifIndex) {
    perror("if_nametoindex");
    Logger::upf_app().error("Interface %s not found", interface.c_str());
    throw std::runtime_error("Interface not found");
  }

  // Retrieve the BPF program based on the section name
  bpf_object__for_each_program(prog, mpSkeleton->obj) {
    // Get section name.
    prog_name = std::string(bpf_program__name(prog));

    if (prog_name == sectionName) {
      // Get programs FD from skeleton object.
      fd = bpf_program__fd(prog);

      if (fd < 0) {
        Logger::upf_app().error(
            "Couldn't get file descriptor for program with section name: %s\n",
            sectionName);
        throw std::runtime_error("File descriptor not found");
      }

      // Create TC-BPF hook
      DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_INGRESS);
      DECLARE_LIBBPF_OPTS(bpf_tc_opts, attach_ingress);

      hook.ifindex           = ifIndex;
      attach_ingress.prog_fd = fd;

      err = bpf_tc_hook_create(&hook);
      if (err && err != -EEXIST) {
        Logger::upf_app().error(
            "Couldn't create TC-BPF hook for interface %s (err:%d)\n",
            interface, err);
        throw std::runtime_error("TC Program not hooked to interface");
      }

      if (err == -EEXIST) {
        Logger::upf_app().info(
            "Success: TC-BPF hook already existed (Ignore: \"libbpf: Kernel "
            "error message: Exclusivity flag on, cannot modify\")\n");
      }

      // Attach the BPF program
      hook.attach_point       = BPF_TC_INGRESS;
      attach_ingress.flags    = BPF_TC_F_REPLACE;
      attach_ingress.handle   = INGRESS_HANDLE;
      attach_ingress.priority = INGRESS_PRIORITY;
      err                     = bpf_tc_attach(&hook, &attach_ingress);
      if (err) {
        Logger::upf_app().error(
            "Couldn't attach ingress program to interface %s (err:%d)\n",
            interface, err);
        throw std::runtime_error(
            "TC Program could not be attached to ingress interface");
      }

      // Add a new entry if doesnt exist.
      // Cc, push back the ney entry to the exist.
      // auto it = mSectionLinkInterfacesMap.find(section);

      auto it = mSectionLinkInterfacesMap.find(prog_name);
      if (it == mSectionLinkInterfacesMap.end()) {
        std::vector<uint32_t> linkVector;
        linkVector.push_back(ifIndex);
        mSectionLinkInterfacesMap[sectionName] = linkVector;
      } else {
        it->second.push_back(ifIndex);
      }

      // Update the global link state.
      mState = ATTACHED_TO_INGRESS;
      Logger::upf_app().info(
          "BPF program %s hooked in %s TC interface", sectionName.c_str(),
          interface.c_str());
      return;
    }
  }

  Logger::upf_app().error("Section %s not found", sectionName.c_str());
  throw std::runtime_error("Section not found");
}

//-------------------------------------------------------------------------------------------------------------
template<class BPFSkeletonType>
void ProgramLifeCycle<BPFSkeletonType>::tcAttachEgress(
    std::string sectionName, std::string interface) {
  int err = 0;
  int fd;
  struct bpf_program* prog = NULL;
  std::string prog_name;

  auto ifIndex = if_nametoindex(interface.c_str());

  if (!ifIndex) {
    perror("if_nametoindex");
    Logger::upf_app().error("Interface %s not found", interface.c_str());
    throw std::runtime_error("Interface not found");
  }

  // Retrieve the BPF program based on the section name
  bpf_object__for_each_program(prog, mpSkeleton->obj) {
    // Get section name.
    prog_name = std::string(bpf_program__name(prog));

    if (prog_name == sectionName) {
      // Get programs FD from skeleton object.
      fd = bpf_program__fd(prog);

      if (fd < 0) {
        Logger::upf_app().error(
            "Couldn't get file descriptor for program with section name: %s\n",
            sectionName);
        throw std::runtime_error("File descriptor not found");
      }

      // Create TC-BPF hook
      DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_EGRESS);
      DECLARE_LIBBPF_OPTS(bpf_tc_opts, attach_egress);

      hook.ifindex          = ifIndex;
      attach_egress.prog_fd = fd;

      err = bpf_tc_hook_create(&hook);
      if (err && err != -EEXIST) {
        Logger::upf_app().error(
            "Couldn't create TC-BPF hook for interface %s\n", interface);
        throw std::runtime_error("TC Program not hooked to interface");
      }

      if (err == -EEXIST) {
        Logger::upf_app().info(
            "Success: TC-BPF hook already existed (Ignore: \"libbpf: Kernel "
            "error message: Exclusivity flag on, cannot modify\")\n");
      }

      // Attach the BPF program
      hook.attach_point      = BPF_TC_EGRESS;
      attach_egress.flags    = BPF_TC_F_REPLACE;
      attach_egress.handle   = EGRESS_HANDLE;
      attach_egress.priority = EGRESS_PRIORITY;
      err                    = bpf_tc_attach(&hook, &attach_egress);
      if (err) {
        Logger::upf_app().error(
            "Couldn't attach egress program to interface %s (err:%d)\n",
            interface, err);
        throw std::runtime_error(
            "TC Program could not be attached to egress interface");
      }

      // Add a new entry if doesnt exist.
      auto it = mSectionLinkInterfacesMap.find(prog_name);
      if (it == mSectionLinkInterfacesMap.end()) {
        std::vector<uint32_t> linkVector;
        linkVector.push_back(ifIndex);
        mSectionLinkInterfacesMap[sectionName] = linkVector;
      } else {
        it->second.push_back(ifIndex);
      }

      // Update the global link state.
      mState = ATTACHED_TO_EGRESS;
      Logger::upf_app().info(
          "BPF program %s hooked in %s TC interface", sectionName.c_str(),
          interface.c_str());
      return;
    }
  }

  Logger::upf_app().error("Section %s not found", sectionName.c_str());
  throw std::runtime_error("Section not found");
}

//-------------------------------------------------------------------------------------------------------------

template<class BPFSkeletonType>
void ProgramLifeCycle<BPFSkeletonType>::tearDown() {
  std::lock_guard<std::mutex> lock(sTearDownMutex);
  struct bpf_program* prog;
  std::string prog_name;

  if (mState != ProgramState::IDLE) {
    if (mState == LINKED) {
      Logger::upf_app().debug("There are some programs in LINKED state");
      bpf_object__for_each_program(prog, mpSkeleton->obj) {
        // Get section name.
        prog_name = std::string(bpf_program__name(prog));

        // Find the section.
        auto it = mSectionLinkInterfacesMap.find(prog_name);

        if (it == mSectionLinkInterfacesMap.end()) {
          Logger::upf_app().debug(
              "BPF program %s are not link to any interface",
              prog_name.c_str());
          continue;
        }
        // For each link in this section, do unlink.
        for (auto linkEntry : it->second) {
          Logger::upf_app().debug(
              "BPF program %s is in a HOOKED state", prog_name.c_str());

          if (bpf_xdp_attach(linkEntry, -1, mFlags, NULL)) {
            Logger::upf_app().error(
                "BPF program %s cannot unlink the %d interface",
                prog_name.c_str(), linkEntry);
            throw std::runtime_error("BPF program cannot unlink");
          };
          Logger::upf_app().info(
              "BPF program %s unlink to %d interface", prog_name.c_str(),
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

//-------------------------------------------------------------------------------------------------------------
template<class BPFSkeletonType>
void ProgramLifeCycle<BPFSkeletonType>::destroy() {
  // Destroy program.
  if (mState != IDLE) {
    mDestroyFunc(mpSkeleton);
  }
  // TODO: Check if it is necessary delete sessionManager here.
  mState = IDLE;
}

//-------------------------------------------------------------------------------------------------------------
template<class BPFSkeletonType>
BPFSkeletonType* ProgramLifeCycle<BPFSkeletonType>::getBPFSkeleton() const {
  return mpSkeleton;
}

//-------------------------------------------------------------------------------------------------------------
template<class BPFSkeletonType>
ProgramState ProgramLifeCycle<BPFSkeletonType>::getState() const {
  return mState;
}

#endif  // __PROGRAMLIFECYCLE_H__
