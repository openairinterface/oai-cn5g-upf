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

add_definitions(-DKERNEL_SPACE)

add_custom_target(upf_ebpf_xdp_all DEPENDS pfcp_session_lookup_ebpf_xdp pfcp_session_pdr_lookup_ebpf_xdp far_ebpf_xdp)

# function(bpf prefix)
#   add_library(${prefix}_ebpf_xdp STATIC ${prefix}_ebpf_xdp_prgrm_kernel.c)
#   add_custom_command(
#     TARGET ${prefix}_ebpf_xdp
#     PRE_LINK
#     COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_SOURCE_DIR}/../skel
#     COMMAND bpftool gen skeleton $<TARGET_OBJECTS:${prefix}_ebpf_xdp> > ${CMAKE_CURRENT_SOURCE_DIR}/../skel/${prefix}_ebpf_xdp_prgrm_kernel_skel.h
#     COMMAND sed -i '9i\#define typeof\(x\) __typeof__\(x\)' ${CMAKE_CURRENT_SOURCE_DIR}/../skel/${prefix}_ebpf_xdp_prgrm_kernel_skel.h
#     DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${prefix}_ebpf_xdp_prgrm_kernel.c
#   )
# endfunction()








function(bpf prefix)
  if (${prefix} STREQUAL "pfcp_session_lookup" OR ${prefix} STREQUAL "pfcp_session_pdr_lookup")
    set(source_dir "${CMAKE_CURRENT_SOURCE_DIR}/rules/pdr")
  elseif (${prefix} STREQUAL "far")
    set(source_dir "${CMAKE_CURRENT_SOURCE_DIR}/rules/far")
  else()
    message(FATAL_ERROR "Invalid prefix: ${prefix}")
  endif()

  add_library(${prefix}_ebpf_xdp STATIC ${source_dir}/${prefix}_ebpf_xdp_prgrm_kernel.c)
  add_custom_command(
    TARGET ${prefix}_ebpf_xdp
    PRE_LINK
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_SOURCE_DIR}/../skel
    COMMAND bpftool gen skeleton $<TARGET_OBJECTS:${prefix}_ebpf_xdp> > ${CMAKE_CURRENT_SOURCE_DIR}/../skel/${prefix}_ebpf_xdp_prgrm_kernel_skel.h
    COMMAND sed -i '9i\#define typeof\(x\) __typeof__\(x\)' ${CMAKE_CURRENT_SOURCE_DIR}/../skel/${prefix}_ebpf_xdp_prgrm_kernel_skel.h
    DEPENDS ${source_dir}/${prefix}_ebpf_xdp_prgrm_kernel.c
  )
endfunction()

bpf(pfcp_session_lookup)
bpf(pfcp_session_pdr_lookup)
bpf(far)
