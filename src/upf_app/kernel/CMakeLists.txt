include(${SRC_TOP_DIR}/upf_app/cmake/toolchain.cmake)

# ---------------------------------------------------------------------------
# Include paths
#
# Hierarchy (low → high specificity):
#   upf_app/            — top-level umbrella
#   upf_app/include/    — shared headers visible to all subsystems
#                         (upf_xdp_limits.h, upf_pipeline_config.h,
#                          upf_network_config.h)
#   upf_app/kernel/     — kernel BPF umbrella
#   kernel/include/     — kernel-only shared headers
#                         (arp_table.h, interfaces.h, upf_xdp_maps.h, …)
#   kernel/pfcp/        — kernel-side PFCP structs
#                         (pfcp_pdr.h, pfcp_far.h, pfcp_qer.h,
#                          pfcp_urr.h, pfcp_bar.h, pfcp_mar.h)
#   kernel/pfcp/ie/     — PFCP IE sub-structs
#   kernel/xdp/         — XDP program source directory
#   kernel/tc/          — TC BPF program source directory
# ---------------------------------------------------------------------------
include_directories(${SRC_TOP_DIR}/upf_app)
include_directories(${SRC_TOP_DIR}/upf_app/include)
include_directories(${SRC_TOP_DIR}/upf_app/kernel)
include_directories(${SRC_TOP_DIR}/upf_app/kernel/include)
include_directories(${SRC_TOP_DIR}/upf_app/kernel/pfcp)
include_directories(${SRC_TOP_DIR}/upf_app/kernel/pfcp/ie)
include_directories(${SRC_TOP_DIR}/upf_app/kernel/xdp)
include_directories(${SRC_TOP_DIR}/upf_app/kernel/tc)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils)

add_definitions(-DKERNEL_SPACE)

if(DEFINED BPF_DEBUG)
  if(BPF_DEBUG)
    add_definitions(-DBPF_DEBUG)
  endif()
endif()

# ---------------------------------------------------------------------------
# Top-level convenience target
# Depends on both XDP and TC skeleton generation.
# ---------------------------------------------------------------------------
add_custom_target(upf_xdp_all DEPENDS upf_xdp qer_tc)

###########################################################################
#               GENERATE eBPF XDP Skeletons                               #
#                                                                         #
# The UPF XDP pipeline uses a single BPF object (upf_xdp_kern.c) that     #
# compiles all tail-call stages into one skeleton:                        #
#                                                                         #
#   Entry programs  (one pair per PDU session type):                      #
#     upf_n3_entry.c / upf_n6_entry.c         — IP PDU                    #
#     upf_n3_eth_entry.c / upf_n6_eth_entry.c — ETH PDU                   #
#                                                                         #
#   Pipeline stages (tail-call PROG_ARRAY, feature_dispatch_map):         #
#     session_lookup_ip.c  — PROG_SESSION_LOOKUP (IP PDU)                 #
#     session_lookup_eth.c — PROG_SESSION_LOOKUP (ETH PDU)                #
#     pdr_match.c          — PROG_PDR_MATCH                               #
#     far_apply.c          — PROG_FAR                                     #
#     qer_apply.c          — PROG_QER  (loaded when enable_qos)           #
#     urr_apply.c          — PROG_URR  (loaded when enable_urr)           #
#     bar_apply.c          — PROG_BAR  (loaded when enable_bar)           #
#     mar_apply.c          — PROG_MAR  (loaded when enable_mar)           #
#     framed_routing_bpf.c — PROG_FRAMED_ROUTING                          #
#     far_broadcast.c      — PROG_ETH_PDU_BROADCAST (ETH PDU only)        #
#                                                                         #
#   Shared kernel structs (included by the above):                        #
#     kernel/pfcp/pfcp_{pdr,far,qer,urr,bar,mar}.h                        #
#     kernel/include/rules_enabled_flags.h                                #
#     kernel/include/eth_session_id.h                                     #
#     kernel/include/upf_xdp_maps.h                                       #
#                                                                         #
# All programs are compiled into one BPF object so that BTF map linking   #
# resolves same-name maps to a single kernel map instance.                #
#                                                                         #
# IMPORTANT: Every .c file in the pipeline is listed in DEPENDS so that   #
# CMake triggers skeleton regeneration whenever any stage changes.        #
###########################################################################
function(xdp arg)
  set(xdp_dir "${CMAKE_CURRENT_SOURCE_DIR}/xdp")
  set(skel_dir "${OPENAIRCN_DIR}/build/upf/build/skel")

  add_library(${arg}_xdp STATIC ${xdp_dir}/${arg}_xdp_kern.c)

  add_custom_command(
    TARGET ${arg}_xdp
    PRE_LINK
    COMMAND ${CMAKE_COMMAND} -E make_directory ${skel_dir}
    COMMAND bpftool gen skeleton $<TARGET_OBJECTS:${arg}_xdp>
            > ${skel_dir}/${arg}_xdp_kern_skel.h
    # Workaround: libbpf skeleton uses typeof() which conflicts with some
    # C++ compilers — inject a compatible macro at line 9.
    COMMAND sed -i '9i\#define typeof\(x\) __typeof__\(x\)'
            ${skel_dir}/${arg}_xdp_kern_skel.h

    # -----------------------------------------------------------------------
    # DEPENDS — list every .c/.h file that feeds into the XDP object.
    # CMake will re-run skeleton generation whenever any of these change.
    # -----------------------------------------------------------------------
    DEPENDS
      # Main entry point (includes all stages below)
      ${xdp_dir}/${arg}_xdp_kern.c

      # Entry programs — one pair per PDU session type
      ${xdp_dir}/upf_n3_entry.c
      ${xdp_dir}/upf_n6_entry.c
      ${xdp_dir}/upf_n3_eth_entry.c
      ${xdp_dir}/upf_n6_eth_entry.c

      # Pipeline tail-call stages
      ${xdp_dir}/session_lookup_ip.c
      ${xdp_dir}/session_lookup_eth.c
      ${xdp_dir}/pdr_match.c
      ${xdp_dir}/far_apply.c
      ${xdp_dir}/qer_apply.c
      ${xdp_dir}/urr_apply.c
      ${xdp_dir}/bar_apply.c
      ${xdp_dir}/mar_apply.c
      ${xdp_dir}/framed_routing_bpf.c
      ${xdp_dir}/far_broadcast.c

      # Shared kernel headers (trigger rebuild on struct changes)
      ${CMAKE_CURRENT_SOURCE_DIR}/pfcp/pfcp_pdr.h
      ${CMAKE_CURRENT_SOURCE_DIR}/pfcp/pfcp_far.h
      ${CMAKE_CURRENT_SOURCE_DIR}/pfcp/pfcp_qer.h
      ${CMAKE_CURRENT_SOURCE_DIR}/pfcp/pfcp_urr.h
      ${CMAKE_CURRENT_SOURCE_DIR}/pfcp/pfcp_bar.h
      ${CMAKE_CURRENT_SOURCE_DIR}/pfcp/pfcp_mar.h
      ${CMAKE_CURRENT_SOURCE_DIR}/include/rules_enabled_flags.h
      ${CMAKE_CURRENT_SOURCE_DIR}/include/eth_session_id.h
      ${CMAKE_CURRENT_SOURCE_DIR}/include/upf_xdp_maps.h
  )
endfunction()

xdp(upf)

###########################################################################
#               GENERATE eBPF TC Skeletons                                #
#                                                                         #
# QER enforcement uses a dedicated TC-BPF skeleton (qer_tc_kern.c).       #
# TC programs attach to the Linux qdisc layer (HTB + BPF classifier)      #
# and are independent of the XDP pipeline above.                          #
#                                                                         #
# The user-space side (QERProgram in user/qer_tc_user.cpp) owns this      #
# skeleton independently of UPF_XDPProgram.                               #
###########################################################################
function(tc arg)
  set(tc_dir  "${CMAKE_CURRENT_SOURCE_DIR}/tc")
  set(skel_dir "${OPENAIRCN_DIR}/build/upf/build/skel")

  add_library(${arg}_tc STATIC ${tc_dir}/${arg}_tc_kern.c)

  add_custom_command(
    TARGET ${arg}_tc
    PRE_LINK
    COMMAND ${CMAKE_COMMAND} -E make_directory ${skel_dir}
    COMMAND bpftool gen skeleton $<TARGET_OBJECTS:${arg}_tc>
            > ${skel_dir}/${arg}_tc_kern_skel.h
    COMMAND sed -i '9i\#define typeof\(x\) __typeof__\(x\)'
            ${skel_dir}/${arg}_tc_kern_skel.h

    DEPENDS
      ${tc_dir}/${arg}_tc_kern.c
      ${CMAKE_CURRENT_SOURCE_DIR}/tc/qer_maps.h
  )
endfunction()

tc(qer)
