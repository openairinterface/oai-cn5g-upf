include(${SRC_TOP_DIR}/upf_app/cmake/toolchain.cmake)
include_directories(${SRC_TOP_DIR}/upf_app)
include_directories(${SRC_TOP_DIR}/upf_app/kernel)
include_directories(${SRC_TOP_DIR}/upf_app/kernel/include)
include_directories(${SRC_TOP_DIR}/upf_app/kernel/pfcp)
include_directories(${SRC_TOP_DIR}/upf_app/kernel/xdp)
include_directories(${SRC_TOP_DIR}/upf_app/kernel/tc)
include_directories(${SRC_TOP_DIR}/upf_app/include)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils)

add_definitions(-DKERNEL_SPACE)

if(DEFINED BPF_DEBUG)
  if(BPF_DEBUG)
    add_definitions(-DBPF_DEBUG)
  endif()
endif()

add_custom_target(upf_xdp_all DEPENDS upf_xdp)

###########################################################################
#                       GENERATE eBPF XDP Skeletons                       #
###########################################################################
function(xdp arg)
  set(source_dir "${CMAKE_CURRENT_SOURCE_DIR}/xdp")
  add_library(${arg}_xdp STATIC ${source_dir}/${arg}_xdp_kern.c)
  add_custom_command(
    TARGET ${arg}_xdp
    PRE_LINK
    COMMAND ${CMAKE_COMMAND} -E make_directory ${OPENAIRCN_DIR}/build/upf/build/skel
    COMMAND bpftool gen skeleton $<TARGET_OBJECTS:${arg}_xdp> > ${OPENAIRCN_DIR}/build/upf/build/skel/${arg}_xdp_kern_skel.h
    COMMAND sed -i '9i\#define typeof\(x\) __typeof__\(x\)' ${OPENAIRCN_DIR}/build/upf/build/skel/${arg}_xdp_kern_skel.h
    DEPENDS ${source_dir}/${arg}_xdp_kern.c
  )
endfunction()

xdp(upf)

###########################################################################
#                       GENERATE eBPF TC Skeletons                        #
###########################################################################
function(tc arg)
  set(source_dir "${CMAKE_CURRENT_SOURCE_DIR}/tc")
  add_library(${arg}_tc STATIC ${source_dir}/${arg}_tc_kernel.c)
  add_custom_command(
    TARGET ${arg}_tc
    PRE_LINK
    COMMAND ${CMAKE_COMMAND} -E make_directory ${OPENAIRCN_DIR}/build/upf/build/skel
    COMMAND bpftool gen skeleton $<TARGET_OBJECTS:${arg}_tc> > ${OPENAIRCN_DIR}/build/upf/build/skel/${arg}_tc_kernel_skel.h
    COMMAND sed -i '9i\#define typeof\(x\) __typeof__\(x\)' ${OPENAIRCN_DIR}/build/upf/build/skel/${arg}_tc_kernel_skel.h
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${arg}_tc_kernel.c
  )
endfunction()

tc(qer)