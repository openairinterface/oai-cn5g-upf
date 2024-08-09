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

add_custom_target(upf_xdp_all DEPENDS pfcp_session_lookup_xdp pfcp_session_pdr_lookup_xdp far_xdp)
add_custom_target(upf_tc_all DEPENDS qer_tc)



###########################################################################
#                       GENERATE eBPF XDP Skeletons                       #
###########################################################################
function(xdp arg)
  if (${arg} STREQUAL "pfcp_session_lookup" OR ${arg} STREQUAL "pfcp_session_pdr_lookup")
    set(source_dir "${CMAKE_CURRENT_SOURCE_DIR}/rules/pdr")
  elseif (${arg} STREQUAL "far")
    set(source_dir "${CMAKE_CURRENT_SOURCE_DIR}/rules/far")
  else()
    message(FATAL_ERROR "Invalid arg: ${arg}")
  endif()

  add_library(${arg}_xdp STATIC ${source_dir}/${arg}_xdp_kernel.c)
  add_custom_command(
    TARGET ${arg}_xdp
    PRE_LINK
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_SOURCE_DIR}/../skel
    COMMAND bpftool gen skeleton $<TARGET_OBJECTS:${arg}_xdp> > ${CMAKE_CURRENT_SOURCE_DIR}/../skel/${arg}_xdp_kernel_skel.h
    COMMAND sed -i '9i\#define typeof\(x\) __typeof__\(x\)' ${CMAKE_CURRENT_SOURCE_DIR}/../skel/${arg}_xdp_kernel_skel.h
    DEPENDS ${source_dir}/${arg}_xdp_kernel.c
  )
endfunction()

xdp(pfcp_session_lookup)
xdp(pfcp_session_pdr_lookup)
xdp(far)



###########################################################################
#                       GENERATE eBPF TC Skeletons                        #
###########################################################################
function(tc arg)
  set(source_dir "${CMAKE_CURRENT_SOURCE_DIR}/rules/qer")
  add_library(${arg}_tc STATIC ${source_dir}/${arg}_tc_kernel.c)
  add_custom_command(
    TARGET ${arg}_tc
    PRE_LINK
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_SOURCE_DIR}/../skel
    COMMAND bpftool gen skeleton $<TARGET_OBJECTS:${arg}_tc> > ${CMAKE_CURRENT_SOURCE_DIR}/../skel/${arg}_tc_kernel_skel.h
    COMMAND sed -i '9i\#define typeof\(x\) __typeof__\(x\)' ${CMAKE_CURRENT_SOURCE_DIR}/../skel/${arg}_tc_kernel_skel.h
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${arg}_tc_kernel.c
  )
endfunction()

tc(qer)