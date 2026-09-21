# SPDX-License-Identifier: LicenseRef-CSSL-1.0
#
# eBPF programs: XDP pipeline + TC-BPF QoS, and their generated libbpf
# skeleton headers.
#
# Layout (low -> high specificity), carried by upf::kernel_headers:
#   upf_app/              umbrella
#   upf_app/include/      shared with user space (upf_xdp_limits.h,
#                         upf_pipeline_config.h, upf_network_config.h)
#   kernel/include/       kernel-only <foo>_types.h / <foo>_maps.h pairs,
#                         tail_call_dispatcher.h, packet_context.h
#   kernel/pfcp/          pfcp_{pdr,far,qer,urr,bar,mar}.h
#   kernel/pfcp/ie/       PFCP IE sub-structs
#   kernel/xdp/, kernel/tc/   program sources

# BPF compile settings. Despite the filename this is NOT a CMAKE_TOOLCHAIN_FILE;
# see the header of that file. Worth renaming to bpf_flags.cmake.
include(${UPF_CMAKE_DIR}/toolchain.cmake)

# -----------------------------------------------------------------------------
# Headers that invalidate every generated skeleton.
#
# Listed once instead of being repeated inside the per-program function, so a
# new shared header is added in one place rather than twelve.
# -----------------------------------------------------------------------------
set(_inc "${CMAKE_CURRENT_SOURCE_DIR}/include")
set(_pfcp "${CMAKE_CURRENT_SOURCE_DIR}/pfcp")

set(UPF_BPF_SHARED_HEADERS
  ${_pfcp}/pfcp_pdr.h ${_pfcp}/pfcp_far.h ${_pfcp}/pfcp_qer.h
  ${_pfcp}/pfcp_urr.h ${_pfcp}/pfcp_bar.h ${_pfcp}/pfcp_mar.h
  ${_inc}/packet_context.h
  ${_inc}/tail_call_dispatcher.h ${_inc}/tail_call_types.h ${_inc}/tail_call_maps.h
  ${_inc}/pipeline_types.h       ${_inc}/pipeline_maps.h
  ${_inc}/interfaces_types.h     ${_inc}/interfaces_maps.h
  ${_inc}/sdf_types.h            ${_inc}/sdf_maps.h
  ${_inc}/arp_types.h            ${_inc}/arp_maps.h
  ${_inc}/eth_pdu_types.h        ${_inc}/eth_pdu_maps.h
  ${_inc}/stats_types.h          ${_inc}/stats_maps.h)

# -----------------------------------------------------------------------------
# Include directories passed to the BPF clang invocation.
#
# Collected once as a -I list. These cannot come from an INTERFACE target: the
# BPF objects are built by an explicit clang command, not by CMake's compiler
# driver, so target usage requirements never reach them.
# -----------------------------------------------------------------------------
set(_bpf_inc_dirs
  "${LIBBPF_INCLUDE_DIR}"
  "${UPF_APP_DIR}"
  "${UPF_APP_DIR}/include"
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/pfcp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pfcp/ie"
  "${CMAKE_CURRENT_SOURCE_DIR}/xdp"
  "${CMAKE_CURRENT_SOURCE_DIR}/tc"
  "${COMMON_SRC_DIR}/utils")

set(UPF_BPF_INCLUDE_FLAGS "")
foreach(d IN LISTS _bpf_inc_dirs)
  list(APPEND UPF_BPF_INCLUDE_FLAGS "-I${d}")
endforeach()

# -----------------------------------------------------------------------------
# upf_bpf_skeleton(<name> <source> <skeleton> [extra deps...])
#
# Compiles one BPF source to an object and generates its libbpf skeleton header.
#
# WHY NOT add_library()
# ---------------------
# The legacy build declared each BPF program as a STATIC library and hung the
# skeleton generation off add_custom_command(TARGET <t> PRE_LINK). That has
# three problems:
#
#   * The archive is never linked into anything, so PRE_LINK fires only as a
#     side effect of building a dead artifact.
#   * The skeleton is not a declared OUTPUT, so CMake cannot tell when it is
#     stale and cannot order a compile that #includes it. Delete a skeleton and
#     it is never regenerated -- the archive is still up to date.
#   * Routing BPF sources through CMake's C compiler driver means the whole
#     directory has to be switched to clang with -target bpf, which is what
#     cmake/toolchain.cmake did globally -- and that leaked onto host code.
#
# An explicit clang invocation makes the .o and the .h ordinary file-level
# outputs with correct dependencies, and confines the BPF triple to exactly the
# commands that need it. (An earlier revision of this file used an OBJECT
# library with $<TARGET_OBJECTS:...> in DEPENDS; under the Makefile generator
# that yields "No rule to make target ...o", because the object path is
# referenced without the rule that builds it being visible in that scope.)
# -----------------------------------------------------------------------------
function(upf_bpf_skeleton name src skel)
  # The object's BASENAME decides the struct name that `bpftool gen skeleton`
  # emits: it sanitises the filename, so xdp_n3_entry_kern.c.o yields
  #   struct xdp_n3_entry_kern_c
  # and all fourteen user/*_user.h headers hardcode that spelling, e.g.
  #   using ProgramLifeCycle<xdp_n3_entry_kern_c>
  # CMake's default object naming (<source>.o) produced it by accident. Naming
  # the object anything else -- xdp_n3_entry.bpf.o, say -- silently renames the
  # generated struct to xdp_n3_entry_bpf and every consumer fails to compile.
  # Keep the source basename verbatim and append .o.
  get_filename_component(_src_name "${src}" NAME)
  set(_obj "${UPF_BPF_OBJ_DIR}/${_src_name}.o")

  add_custom_command(
    OUTPUT  "${_obj}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${UPF_BPF_OBJ_DIR}"
    COMMAND ${UPF_BPF_CLANG} ${UPF_BPF_CFLAGS} ${UPF_BPF_INCLUDE_FLAGS}
            -c "${src}" -o "${_obj}"
    DEPENDS "${src}" ${UPF_BPF_SHARED_HEADERS} ${ARGN}
    COMMENT "Compiling BPF object ${name}.bpf.o"
    VERBATIM)

  add_custom_command(
    OUTPUT  "${skel}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${UPF_SKEL_DIR}"
    COMMAND ${UPF_BPFTOOL} gen skeleton "${_obj}" > "${skel}"
    # libbpf's generated skeleton uses typeof(), a GNU extension that clang++
    # rejects under -std=c++17 with CMAKE_CXX_EXTENSIONS OFF. Inject the
    # portable spelling at line 9, just after the include guard.
    COMMAND sed -i "9i\\#define typeof(x) __typeof__(x)" "${skel}"
    DEPENDS "${_obj}"
    COMMENT "Generating BPF skeleton ${name}"
    VERBATIM)
endfunction()

# -----------------------------------------------------------------------------
# XDP pipeline
#
# Entry programs attach directly to the N3/N6 interfaces; pipeline stages are
# loaded into tail_call_progs_map slots 0-7 and reached by bpf_tail_call().
# -----------------------------------------------------------------------------
set(UPF_XDP_PROGRAMS
  xdp_n3_entry            # IP  PDU uplink   (N3 -> N6)
  xdp_n6_entry            # IP  PDU downlink (N6 -> N3)
  xdp_n3_eth_entry        # ETH PDU uplink
  xdp_n6_eth_entry        # ETH PDU downlink
  xdp_session_lookup_ip   # slot 0  PROG_SESSION_LOOKUP_IP
  xdp_session_lookup_eth  # slot 1  PROG_SESSION_LOOKUP_ETH
  xdp_pdr_match           # slot 2  PROG_PDR_MATCH
  xdp_far_apply           # slot 3  PROG_FAR_APPLY
  xdp_qer_apply           # slot 4  PROG_QER_APPLY  (enable_qer)
  xdp_urr_apply           # slot 5  PROG_URR_APPLY  (enable_urr)
  xdp_bar_apply           # slot 6  PROG_BAR_APPLY  (enable_bar)
  xdp_mar_apply)          # slot 7  PROG_MAR_APPLY  (enable_mar)

set(_xdp_skeletons "")
foreach(stem IN LISTS UPF_XDP_PROGRAMS)
  set(_skel "${UPF_SKEL_DIR}/${stem}_skel.h")
  upf_bpf_skeleton(${stem}
                   "${CMAKE_CURRENT_SOURCE_DIR}/xdp/${stem}_kern.c"
                   "${_skel}")
  list(APPEND _xdp_skeletons "${_skel}")
endforeach()

# INTERFACE library carrying the skeleton directory as a usage requirement, so
# consumers get -I${UPF_SKEL_DIR} by linking it.
#
# It does NOT order the generation. add_dependencies() on an INTERFACE library
# is not propagated to targets that merely link it, so a consumer still needs an
# explicit add_dependencies(<consumer> upf_xdp_all) or it will race the skeleton
# generation and fail with "xdp_*_skel.h: No such file or directory" on a clean
# build. (Incremental builds hide this: once the headers exist they stay.)
add_custom_target(upf_xdp_skeletons DEPENDS ${_xdp_skeletons})
add_library(upf_xdp INTERFACE)
target_include_directories(upf_xdp INTERFACE "${UPF_SKEL_DIR}")
add_dependencies(upf_xdp upf_xdp_skeletons)

# -----------------------------------------------------------------------------
# TC-BPF programs
#
# QER enforcement (HTB qdisc + BPF classifier, per-QFI MBR/GBR) and ETH
# broadcast. These attach at the qdisc layer and are independent of the XDP
# pipeline; the user-space side owns their skeletons separately.
# -----------------------------------------------------------------------------
function(upf_tc_program name helper_header)
  set(_skel "${UPF_SKEL_DIR}/${name}_tc_kern_skel.h")
  # The helper header is a per-program dependency, passed as a trailing arg
  # rather than added to the shared header list.
  upf_bpf_skeleton(${name}_tc
                   "${CMAKE_CURRENT_SOURCE_DIR}/tc/${name}_tc_kern.c"
                   "${_skel}"
                   "${CMAKE_CURRENT_SOURCE_DIR}/tc/${helper_header}")

  add_custom_target(${name}_tc_skeleton DEPENDS "${_skel}")
  add_library(${name}_tc INTERFACE)
  target_include_directories(${name}_tc INTERFACE "${UPF_SKEL_DIR}")
  add_dependencies(${name}_tc ${name}_tc_skeleton)
endfunction()

upf_tc_program(qer            qer_maps.h)
upf_tc_program(eth_broadcast  eth_broadcast.h)

# Convenience aggregate, kept for compatibility with existing
# add_dependencies(<lib> upf_xdp_all) call sites.
add_custom_target(upf_xdp_all)
add_dependencies(upf_xdp_all upf_xdp qer_tc eth_broadcast_tc)
