include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/toolchain.cmake)

add_subdirectory(kernel)

# ==========================================================================
# Global include paths
#
# Ordered from most general to most specific.  Headers shared across
# control/, user/, simpleswitch/ go in include/ or kernel/include/.
# Headers that belong to a single subsystem stay local to that target.
# ==========================================================================

# OAI common / external
include_directories(${SRC_TOP_DIR}/common)
include_directories(${SRC_TOP_DIR}/common/msg)
include_directories(${SRC_TOP_DIR}/common/utils)
include_directories(${SRC_TOP_DIR}/gtpv1u)
include_directories(${SRC_TOP_DIR}/itti)
include_directories(${SRC_TOP_DIR}/pfcp)
include_directories(${SRC_TOP_DIR}/udp)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/3gpp)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/common)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/config)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/pfcp)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils/bstr)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/common_model)

include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/nrf/nrf_model.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils/utils.cmake)

# upf_app — shared across all subsystems
include_directories(${SRC_TOP_DIR}/upf_app)
include_directories(${SRC_TOP_DIR}/upf_app/include)       # upf_network_config.h, upf_xdp_limits.h
include_directories(${SRC_TOP_DIR}/upf_app/utils)
include_directories(${SRC_TOP_DIR}/upf_app/app)
include_directories(${SRC_TOP_DIR}/upf_app/control)
include_directories(${SRC_TOP_DIR}/upf_app/helpers)        # CmdRunner, SdfFilterParser, GetNicInformation, NextHopFinder
include_directories(${SRC_TOP_DIR}/upf_app/simpleswitch)
include_directories(${SRC_TOP_DIR}/upf_app/user)           # BPFProgram, *_xdp_user, qer_tc_user, pdr_match_user
include_directories(${SRC_TOP_DIR}/upf_app/framed_routing) # framed_routing_bpf.h, FramedRouting.hpp

# Kernel BPF headers — shared between kernel programs and user-space wrappers
include_directories(${SRC_TOP_DIR}/upf_app/kernel)
include_directories(${SRC_TOP_DIR}/upf_app/kernel/include) # arp_table.h, interfaces.h, upf_xdp_maps.h,
                                                            # rules_enabled_flags.h, eth_session_id.h
include_directories(${SRC_TOP_DIR}/upf_app/kernel/pfcp)    # pfcp_{pdr,far,qer,urr,bar,mar}.h
include_directories(${SRC_TOP_DIR}/upf_app/kernel/pfcp/ie) # IE sub-structs (pdi.h, create_far.h, …)
include_directories(${SRC_TOP_DIR}/upf_app/kernel/xdp)     # tail_call_dispatch.h, session_id.h, …
include_directories(${SRC_TOP_DIR}/upf_app/kernel/tc)      # qer_maps.h

set(CMAKE_C_FLAGS "-Wno-gnu-variable-sized-type-not-at-end")

# ==========================================================================
# Common source files shared by both UPF_XDP and UPF_TC libraries
#
# Split into logical groups for readability.  Any file added to one library
# that belongs to shared logic should be added here unless it is genuinely
# library-specific (e.g. the program-type .cpp files).
# ==========================================================================
set(UPF_CONTROL_SOURCES
  control/UserPlaneComponent.cpp
  control/Configuration.cpp
  control/SignalHandler.cpp
  control/SessionProgramManager.cpp
  control/SessionManager.cpp
  control/SessionPrograms.cpp
)

set(UPF_HELPER_SOURCES
  helpers/CmdRunner.cpp
  helpers/GetNicInformation.cpp
  helpers/NextHopFinder.cpp
  helpers/SdfFilterParser.cpp
)

# User-space program wrappers shared between both datapath libraries.
# URR, BAR, MAR and PDR match wrappers are map-only managers that work
# regardless of whether the XDP or TC path is active.
set(UPF_USER_SHARED_SOURCES
  user/far_apply_user.cpp
  user/mar_apply_user.cpp
  user/qer_tc_user.cpp
  user/urr_apply_user.cpp
  user/bar_apply_user.cpp
  user/pdr_match_user.cpp
  user/upf_xdp_user.cpp
  user/session_lookup_ip_user.cpp
  user/session_lookup_eth_user.cpp  
  user/BPFProgram.cpp
  user/wrappers/BPFMap.cpp
  user/wrappers/BPFMaps.cpp
  user/utils/bpf_utils.cpp
  user/utils/net_utils.cpp
)




# ==========================================================================
# UPF_XDP — XDP fast-path dataplane library
#
# Owns the upf_xdp_kern skeleton (all tail-call pipeline programs) and the
# UPF_XDPProgram class that manages program attachment and map population.
# ==========================================================================

set(GTP_INTERFACE $ENV{GTP_INTERFACE})
set(UDP_INTERFACE $ENV{UDP_INTERFACE})
set(SOCKET_BUFFER_ENABLED $ENV{SOCKET_BUFFER_ENABLED})

add_library(UPF_XDP STATIC
  ${UPF_CONTROL_SOURCES}
  ${UPF_HELPER_SOURCES}
  ${UPF_USER_SHARED_SOURCES}
  user/upf_xdp_user.cpp         # UPF_XDPProgram — XDP skeleton owner
)

target_include_directories(UPF_XDP PUBLIC
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/include>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/control>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/helpers>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/user>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/kernel> 
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/kernel/include>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/kernel/pfcp>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/kernel/pfcp/ie>
  $<BUILD_INTERFACE:${OPENAIRCN_DIR}/build/upf/build/skel>  # generated skeletons
)

link_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../build/ext/libbpf/src)

target_link_libraries(UPF_XDP
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../build/ext/libbpf/src/libbpf.a
  ${CMAKE_CURRENT_SOURCE_DIR}/../../build/ext/libbpf/src/libbpf.so
  PRIVATE elf
  PRIVATE z qer_tc   # TC skeleton needed for QERProgram
)

add_dependencies(UPF_XDP upf_xdp_all)

install(
    TARGETS UPF_XDP
    EXPORT "${TARGETS_EXPORT_NAME}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

# ==========================================================================
# UPF_TC — TC-BPF QoS enforcement library
#
# Owns the qer_tc_kern skeleton and QERProgram class (HTB qdisc + TC-BPF
# classifier for per-QFI MBR/GBR enforcement).  Shares all control-plane
# and helper sources with UPF_XDP.
# ==========================================================================
include_directories(${SRC_TOP_DIR}/upf_app/kernel/tc)

add_library(UPF_TC STATIC
  ${UPF_CONTROL_SOURCES}
  ${UPF_HELPER_SOURCES}
  ${UPF_USER_SHARED_SOURCES}
  user/qer_tc_user.cpp          # QERProgram — TC-BPF skeleton owner
)

target_include_directories(UPF_TC PUBLIC
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/include>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/control>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/helpers>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/user>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/kernel>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/kernel/include>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/kernel/pfcp>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/kernel/pfcp/ie>
  $<BUILD_INTERFACE:${OPENAIRCN_DIR}/build/upf/build/skel>  # generated skeletons
)

  target_link_libraries(UPF_TC
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../build/ext/libbpf/src/libbpf.a
  ${CMAKE_CURRENT_SOURCE_DIR}/../../build/ext/libbpf/src/libbpf.so.1
  PRIVATE elf
  PRIVATE z
  libnl-3.so
  libnl-route-3.so
)

  add_dependencies(UPF_TC upf_xdp_all)

  add_dependencies(UPF_TC upf_xdp_all)
  
  install(
      TARGETS UPF_TC
      EXPORT "${TARGETS_EXPORT_NAME}"
      LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
      ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
      RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
      INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  )

