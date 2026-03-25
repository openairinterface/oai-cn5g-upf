include(${SRC_TOP_DIR}/upf_app/cmake/toolchain.cmake)

# =============================================================================== #
# Include paths                                                                   #
#                                                                                 #
# Hierarchy (low -> high specificity):                                            #
#   upf_app/              -- top-level umbrella                                   #
#   upf_app/include/      -- shared headers visible to all subsystems             #
#                           (upf_xdp_limits.h, upf_pipeline_config.h,             #
#                            upf_network_config.h)                                #
#   upf_app/kernel/       -- kernel BPF umbrella                                  #
#   kernel/include/       -- kernel-only shared headers (new split layout):       #
#                           interfaces_types.h / interfaces_maps.h                #
#                           arp_types.h       / arp_maps.h                        #
#                           sdf_types.h       / sdf_maps.h                        #
#                           pipeline_types.h  / pipeline_maps.h                   #
#                           eth_pdu_types.h   / eth_pdu_maps.h                    #
#                           tail_call_types.h / tail_call_maps.h                  #
#                           tail_call_dispatcher.h                                #
#                           stats_types.h     / stats_maps.h                      #
#                           packet_context.h                                      #
#                           urr_types.h / urr_maps.h                              #
#                           bar_types.h / bar_maps.h                              #
#                           mar_types.h / mar_maps.h                              #
#   kernel/pfcp/          -- kernel-side PFCP structs                             #
#                           (pfcp_pdr.h, pfcp_far.h, pfcp_qer.h,                  #
#                            pfcp_urr.h, pfcp_bar.h, pfcp_mar.h)                  #
#   kernel/pfcp/ie/       -- PFCP IE sub-structs                                  #
#   kernel/xdp/           -- XDP program source directory                         #
#   kernel/tc/            -- TC BPF program source directory                      #
# =============================================================================== #
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


# =============================================================================== #
#                         Top-level convenience target                            #
#               Depends on both XDP and TC skeleton generation.                   #
# =============================================================================== #
add_custom_target(upf_xdp_all DEPENDS upf_xdp qer_tc)



# =============================================================================== #
#               GENERATE eBPF XDP Skeletons                                       #
#                                                                                 #
# Each XDP program is compiled as a separate BPF object.                          #
# Source files follow the naming convention: <source_stem>_kern.c                 #
# Generated skeleton: build/upf/build/skel/<source_stem>_skel.h                   #
#                                                                                 #
# Entry programs (attached directly to interfaces via XDP hook):                  #
#   xdp_n3_entry_kern.c         -- IP  PDU uplink   (N3 -> N6)                    #
#   xdp_n6_entry_kern.c         -- IP  PDU downlink (N6 -> N3)                    #
#   xdp_n3_eth_entry_kern.c     -- ETH PDU uplink   (N3 -> N6)                    #
#   xdp_n6_eth_entry_kern.c     -- ETH PDU downlink (N6 -> N3)                    #
#                                                                                 #
# Pipeline stages (loaded into tail_call_progs_map PROG_ARRAY slots 0-7):         #
#   xdp_session_lookup_ip_kern.c  -- slot 0   PROG_SESSION_LOOKUP_IP              #
#   xdp_session_lookup_eth_kern.c -- slot 1   PROG_SESSION_LOOKUP_ETH             #
#   xdp_pdr_match_kern.c          -- slot 2   PROG_PDR_MATCH                      #
#   xdp_far_apply_kern.c          -- slot 3   PROG_FAR_APPLY                      #
#   xdp_qer_apply_kern.c          -- slot 4   PROG_QER_APPLY  (enable_qos)        #
#   xdp_urr_apply_kern.c          -- slot 5   PROG_URR_APPLY  (enable_urr)        #
#   xdp_bar_apply_kern.c          -- slot 6   PROG_BAR_APPLY  (enable_bar)        #
#   xdp_mar_apply_kern.c          -- slot 7   PROG_MAR_APPLY  (enable_mar)        #
#                                                                                 #
# Shared kernel headers (trigger rebuild on any struct change):                   #
#   kernel/pfcp/pfcp_{pdr,far,qer,urr,bar,mar}.h                                  #
#   kernel/include/tail_call_dispatcher.h                                         #
#   kernel/include/packet_context.h                                               #
#   kernel/include/pipeline_maps.h                                                #
#   kernel/include/pipeline_types.h                                               #
#                                                                                 #
# =============================================================================== #

# =============================================================================== #
# xdp_program(<source_stem>)                                                      #
#                                                                                 #
# Compiles one XDP BPF source file and generates its libbpf skeleton header.      #
#                                                                                 #
#   <source_stem>  -- filename without _kern.c suffix (e.g. "xdp_n3_entry")       #
#                                                                                 #
# Source file:      kernel/xdp/<source_stem>_kern.c                               #
# Output skeleton:  build/upf/build/skel/<source_stem>_skel.h                     #
# CMake target:     <source_stem>_xdp_obj                                         #
# =============================================================================== #

function(xdp_program source_stem)
  set(xdp_dir  "${CMAKE_CURRENT_SOURCE_DIR}/xdp")
  set(inc_dir  "${CMAKE_CURRENT_SOURCE_DIR}/include")
  set(skel_dir "${OPENAIRCN_DIR}/build/upf/build/skel")

  set(src_file "${xdp_dir}/${source_stem}_kern.c")
  set(obj_name "${source_stem}_xdp_obj")
  set(skel_hdr "${skel_dir}/${source_stem}_skel.h")

  # Compile the BPF object
  add_library(${obj_name} STATIC ${src_file})

  # Generate the libbpf skeleton header from the compiled object
  add_custom_command(
    TARGET ${obj_name}
    PRE_LINK
    COMMAND ${CMAKE_COMMAND} -E make_directory ${skel_dir}
    COMMAND bpftool gen skeleton $<TARGET_OBJECTS:${obj_name}>
            > ${skel_hdr}
    # Workaround: libbpf skeleton uses typeof() which conflicts with some
    # C++ compilers -- inject a compatible macro at line 9.
    COMMAND sed -i '9i\#define typeof\(x\) __typeof__\(x\)'
            ${skel_hdr}

    DEPENDS
      ${src_file}

      # PFCP struct headers -- rebuild skeleton if any rule struct changes
      ${CMAKE_CURRENT_SOURCE_DIR}/pfcp/pfcp_pdr.h
      ${CMAKE_CURRENT_SOURCE_DIR}/pfcp/pfcp_far.h
      ${CMAKE_CURRENT_SOURCE_DIR}/pfcp/pfcp_qer.h
      ${CMAKE_CURRENT_SOURCE_DIR}/pfcp/pfcp_urr.h
      ${CMAKE_CURRENT_SOURCE_DIR}/pfcp/pfcp_bar.h
      ${CMAKE_CURRENT_SOURCE_DIR}/pfcp/pfcp_mar.h

      # Core pipeline types/maps -- rebuild on any struct or map change
      ${inc_dir}/packet_context.h
      ${inc_dir}/tail_call_dispatcher.h
      ${inc_dir}/tail_call_types.h
      ${inc_dir}/tail_call_maps.h
      ${inc_dir}/pipeline_types.h
      ${inc_dir}/pipeline_maps.h
      ${inc_dir}/interfaces_types.h
      ${inc_dir}/interfaces_maps.h
      ${inc_dir}/sdf_types.h
      ${inc_dir}/sdf_maps.h
      ${inc_dir}/arp_types.h
      ${inc_dir}/arp_maps.h
      ${inc_dir}/eth_pdu_types.h
      ${inc_dir}/eth_pdu_maps.h
      ${inc_dir}/stats_types.h
      ${inc_dir}/stats_maps.h
  )
endfunction()

# ---------------------------------------------------------------------------
# xdp(<group_name>)
#
# Top-level wrapper: compiles all XDP programs in the pipeline and
# groups their object targets under a single "<group_name>_xdp" INTERFACE
# library for dependency tracking by upf_xdp_all.
# ---------------------------------------------------------------------------
function(xdp arg)
  # -- Entry programs (attached directly to N3/N6 interfaces) ---------------
  xdp_program(xdp_n3_entry)
  xdp_program(xdp_n6_entry)
  xdp_program(xdp_n3_eth_entry)
  xdp_program(xdp_n6_eth_entry)

  # -- Pipeline tail-call stages (slot 0-7 in tail_call_progs_map) ----------
  xdp_program(xdp_session_lookup_ip)
  xdp_program(xdp_session_lookup_eth)
  xdp_program(xdp_pdr_match)
  xdp_program(xdp_far_apply)
  xdp_program(xdp_qer_apply)
  xdp_program(xdp_urr_apply)
  xdp_program(xdp_bar_apply)
  xdp_program(xdp_mar_apply)

  # INTERFACE library so the parent CMakeLists can call
  # target_link_libraries(upf ... upf_xdp) without a linker error.
  # INTERFACE libraries have no compiled sources of their own — they exist
  # as a named linkable target that carries build dependencies.
  add_library(${arg}_xdp INTERFACE)

  add_dependencies(${arg}_xdp
    xdp_n3_entry_xdp_obj
    xdp_n6_entry_xdp_obj
    xdp_n3_eth_entry_xdp_obj
    xdp_n6_eth_entry_xdp_obj
    xdp_session_lookup_ip_xdp_obj
    xdp_session_lookup_eth_xdp_obj
    xdp_pdr_match_xdp_obj
    xdp_far_apply_xdp_obj
    xdp_qer_apply_xdp_obj
    xdp_urr_apply_xdp_obj
    xdp_bar_apply_xdp_obj
    xdp_mar_apply_xdp_obj
  )
endfunction()

xdp(upf)




# =============================================================================== #
#               GENERATE eBPF TC Skeletons                                        #
#                                                                                 #
# QER enforcement uses a dedicated TC-BPF skeleton (qer_tc_kern.c).               #
# TC programs attach to the Linux qdisc layer (HTB + BPF classifier)              #
# and are independent of the XDP pipeline above.                                  #
#                                                                                 #
# The user-space side (QERProgram in user/qer_tc_user.cpp) owns this              #
# skeleton independently of UPF_XDPProgram.                                       #
# =============================================================================== #
function(tc arg)
  set(tc_dir   "${CMAKE_CURRENT_SOURCE_DIR}/tc")
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
      ${tc_dir}/${arg}_maps.h
  )
endfunction()

tc(qer)
