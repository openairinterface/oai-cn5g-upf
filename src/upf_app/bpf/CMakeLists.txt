include(${SRC_TOP_DIR}/upf_app/cmake/toolchain.cmake)
include_directories(${SRC_TOP_DIR}/upf_app)
include_directories(${SRC_TOP_DIR}/upf_app/bpf)
include_directories(${SRC_TOP_DIR}/upf_app/bpf/rules)
include_directories(${SRC_TOP_DIR}/upf_app/bpf/rules/include)
include_directories(${SRC_TOP_DIR}/upf_app/bpf/rules/pdr)
include_directories(${SRC_TOP_DIR}/upf_app/bpf/rules/far)
include_directories(${SRC_TOP_DIR}/upf_app/bpf/rules/qer)
#include_directories(${SRC_TOP_DIR}/upf_app/bpf/rules/urr)
#include_directories(${SRC_TOP_DIR}/upf_app/bpf/rules/bar)
#include_directories(${SRC_TOP_DIR}/upf_app/bpf/rules/mar)
include_directories(${SRC_TOP_DIR}/upf_app/include)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils)

add_definitions(-DKERNEL_SPACE)

add_custom_target(upf_ebpf_xdp_all DEPENDS pfcp_session_lookup_ebpf_xdp pfcp_session_pdr_lookup_ebpf_xdp far_ebpf_xdp)
add_custom_target(upf_ebpf_tc_all DEPENDS qer_ebpf_tc)



###########################################################################
#                       GENERATE eBPF XDP Skeletons                       #
###########################################################################
function(ebpf_xdp arg)
  if (${arg} STREQUAL "pfcp_session_lookup" OR ${arg} STREQUAL "pfcp_session_pdr_lookup")
    set(source_dir "${CMAKE_CURRENT_SOURCE_DIR}/rules/pdr")
  elseif (${arg} STREQUAL "far")
    set(source_dir "${CMAKE_CURRENT_SOURCE_DIR}/rules/far")
  else()
    message(FATAL_ERROR "Invalid arg: ${arg}")
  endif()

  add_library(${arg}_ebpf_xdp STATIC ${source_dir}/${arg}_ebpf_xdp_prgrm_kernel.c)
  add_custom_command(
    TARGET ${arg}_ebpf_xdp
    PRE_LINK
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_SOURCE_DIR}/../skel
    COMMAND bpftool gen skeleton $<TARGET_OBJECTS:${arg}_ebpf_xdp> > ${CMAKE_CURRENT_SOURCE_DIR}/../skel/${arg}_ebpf_xdp_prgrm_kernel_skel.h
    COMMAND sed -i '9i\#define typeof\(x\) __typeof__\(x\)' ${CMAKE_CURRENT_SOURCE_DIR}/../skel/${arg}_ebpf_xdp_prgrm_kernel_skel.h
    DEPENDS ${source_dir}/${arg}_ebpf_xdp_prgrm_kernel.c
  )
endfunction()

ebpf_xdp(pfcp_session_lookup)
ebpf_xdp(pfcp_session_pdr_lookup)
ebpf_xdp(far)



###########################################################################
#                       GENERATE eBPF TC Skeletons                        #
###########################################################################
function(ebpf_tc arg)
  set(source_dir "${CMAKE_CURRENT_SOURCE_DIR}/rules/qer")
  add_library(${arg}_ebpf_tc STATIC ${source_dir}/${arg}_ebpf_tc_prgrm_kernel.c)
  add_custom_command(
    TARGET ${arg}_ebpf_tc
    PRE_LINK
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_SOURCE_DIR}/../skel
    COMMAND bpftool gen skeleton $<TARGET_OBJECTS:${arg}_ebpf_tc> > ${CMAKE_CURRENT_SOURCE_DIR}/../skel/${arg}_ebpf_tc_prgrm_kernel_skel.h
    COMMAND sed -i '9i\#define typeof\(x\) __typeof__\(x\)' ${CMAKE_CURRENT_SOURCE_DIR}/../skel/${arg}_ebpf_tc_prgrm_kernel_skel.h
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${arg}_ebpf_tc_prgrm_kernel.c
  )
endfunction()

ebpf_tc(qer)
