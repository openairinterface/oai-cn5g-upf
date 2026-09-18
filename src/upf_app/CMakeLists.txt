# SPDX-License-Identifier: LicenseRef-CSSL-1.0
#
# UPF_XDP / UPF_TC -- the two datapath libraries.
#
# Both share the entire control plane, the helper layer and the user-space BPF
# wrappers; they differ only in which skeleton they own (XDP pipeline vs TC-BPF
# QoS). The shared sources are compiled once into an OBJECT library rather than
# twice, and the BPF settings that the legacy file applied globally now live on
# the BPF targets in kernel/.

add_subdirectory(kernel)

# -----------------------------------------------------------------------------
# Shared sources
#
# UPF_CONTROL / UPF_HELPER / UPF_USER_SHARED were three separate lists that were
# expanded into both libraries, so every file was compiled twice. An OBJECT
# library compiles them once and both libraries reuse the objects.
#
# Two files were also listed twice within a single library:
#   user/upf_xdp_user.cpp -- in UPF_USER_SHARED_SOURCES (:95) and again
#                            explicitly in add_library(UPF_XDP …) (:127)
#   user/qer_tc_user.cpp  -- in UPF_USER_SHARED_SOURCES (:89) and again
#                            explicitly in add_library(UPF_TC …) (:177)
# Each is listed exactly once below, in the group it belongs to.
# -----------------------------------------------------------------------------
add_library(upf_datapath_common OBJECT
  # Control plane
  control/Configuration.cpp
  control/SessionManager.cpp
  control/SessionProgramManager.cpp
  control/SessionPrograms.cpp
  control/SignalHandler.cpp
  control/UserPlaneComponent.cpp

  # Helpers
  helpers/CmdRunner.cpp
  helpers/GetNicInformation.cpp
  helpers/NextHopFinder.cpp
  helpers/SdfFilterParser.cpp

  # User-space BPF wrappers. The URR/BAR/MAR/PDR-match wrappers are map-only
  # managers and work regardless of which datapath is active.
  user/BPFProgram.cpp
  user/bar_apply_user.cpp
  user/eth_broadcast_tc_user.cpp
  user/far_apply_user.cpp
  user/mar_apply_user.cpp
  user/n3_entry_user.cpp
  user/n3_eth_entry_user.cpp
  user/n6_entry_user.cpp
  user/n6_eth_entry_user.cpp
  user/pdr_match_user.cpp
  user/qer_apply_user.cpp
  user/session_lookup_eth_user.cpp
  user/session_lookup_ip_user.cpp
  user/urr_apply_user.cpp
  user/utils/bpf_utils.cpp
  user/utils/net_utils.cpp
  user/wrappers/BPFMap.cpp
  user/wrappers/BPFMaps.cpp)

# PUBLIC on an OBJECT library propagates to whatever links it, so both
# datapath libraries inherit these without repeating them.
target_include_directories(upf_datapath_common PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${CMAKE_CURRENT_SOURCE_DIR}/app"
  "${CMAKE_CURRENT_SOURCE_DIR}/control"
  "${CMAKE_CURRENT_SOURCE_DIR}/helpers"
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/simpleswitch"
  "${CMAKE_CURRENT_SOURCE_DIR}/user"
  "${CMAKE_CURRENT_SOURCE_DIR}/utils")

# upf_app/app/upf_config.hpp includes <gtpv1u.hpp>, so the control-plane
# sources need GTPV1U's headers. Linking the target carries them.
target_link_libraries(upf_datapath_common PUBLIC
  upf::core
  oai::common
  GTPV1U
  PFCP
  UDP
  upf::kernel_headers
  libbpf::bpf          # carries LIBBPF_INCLUDE_DIR and the elf/z system deps
  upf_xdp              # carries UPF_SKEL_DIR and orders skeleton generation
  qer_tc
  eth_broadcast_tc)

# The legacy file did `set(CMAKE_C_FLAGS "-Wno-gnu-variable-sized-type-not-at-end")`
# -- an assignment, not an append, discarding everything set upstream. The
# warning only concerns libbpf's map definitions, so it is scoped to the targets
# that actually include them. It is a clang spelling; GCC warns
# "unrecognized command-line option" on every single file compiled, so it is
# guarded by compiler id rather than passed unconditionally.
target_compile_options(upf_datapath_common PRIVATE
  $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wno-gnu-variable-sized-type-not-at-end>)

# -----------------------------------------------------------------------------
# UPF_XDP -- XDP fast-path datapath
#
# Owns UPF_XDPProgram: attaches the tail-call pipeline and populates its maps.
# -----------------------------------------------------------------------------
add_library(UPF_XDP STATIC
  user/upf_xdp_user.cpp)

target_link_libraries(UPF_XDP PUBLIC upf_datapath_common)

# -----------------------------------------------------------------------------
# UPF_TC -- TC-BPF QoS enforcement
#
# Owns QERProgram: the HTB qdisc plus the per-QFI MBR/GBR BPF classifier.
#
# It drives the qdisc layer by shelling out to the `tc` command line, not
# through any netlink library: user/qer_tc_user.cpp formats strings such as
#   "tc qdisc add dev {} root handle 1:0 htb default {} r2q {}"
#   "tc filter add dev {} parent 1:0 protocol ip bpf obj ..."
# and runs them via CmdRunner::exec(), which is a popen() wrapper.
#
# The legacy build linked `libnl-3.so` and `libnl-route-3.so` here by bare
# filename. Nothing in the tree includes a netlink header or calls a libnl
# symbol, and the linker dropped both as unneeded -- `ldd` on the resulting
# binary lists neither, and `nm -uC` reports zero undefined libnl symbols. The
# dependency was never real, so it is gone along with find_package(LibNL) and
# cmake/FindLibNL.cmake.
# -----------------------------------------------------------------------------
add_library(UPF_TC STATIC
  user/qer_tc_user.cpp)

target_link_libraries(UPF_TC PUBLIC upf_datapath_common)

# -----------------------------------------------------------------------------
# Notes on what was removed
#
# * link_directories(.../build/ext/libbpf/src) at :144 came AFTER
#   add_library(UPF_XDP) at :123. link_directories only affects targets created
#   after the call, so it never applied to UPF_XDP at all. The absolute path is
#   now carried by the libbpf::bpf imported target.
#
# * UPF_XDP linked libbpf.a AND libbpf.so; UPF_TC linked libbpf.a AND
#   libbpf.so.1. Linking the static and shared build of one library into the
#   same target gives duplicate definitions and leaves resolution to link order.
#   libbpf::bpf links the static archive only.
#
# * add_dependencies(UPF_TC upf_xdp_all) appeared twice, verbatim (:203, :205).
#   The dependency is now implicit in target_link_libraries(upf_xdp …).
#
# * set(GTP_INTERFACE $ENV{GTP_INTERFACE}), and the same for UDP_INTERFACE and
#   SOCKET_BUFFER_ENABLED (:119-121), were read from the environment and never
#   used by any list file or source file in the tree.
#
# * include_directories(${SRC_TOP_DIR}/upf_app/kernel/tc) at :171 repeated :56.
# -----------------------------------------------------------------------------

include(GNUInstallDirs)
install(TARGETS UPF_XDP UPF_TC
  EXPORT      "${TARGETS_EXPORT_NAME}"
  LIBRARY     DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  ARCHIVE     DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  RUNTIME     DESTINATION "${CMAKE_INSTALL_BINDIR}"
  INCLUDES    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
