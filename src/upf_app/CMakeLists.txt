# SPDX-License-Identifier: LicenseRef-CSSL-1.0

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/toolchain.cmake)

add_subdirectory(kernel)
include_directories(${SRC_TOP_DIR}/upf_app/kernel/bpf_pfcp)
include_directories(${SRC_TOP_DIR}/upf_app/simpleswitch)
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
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/nrf/nrf_model.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils/utils.cmake)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/common_model.cmake)

include_directories(${SRC_TOP_DIR}/upf_app/kernel)
include_directories(${SRC_TOP_DIR}/upf_app/kernel/include)
include_directories(${SRC_TOP_DIR}/upf_app/kernel/pfcp)


##############################################################
#                          XDP                               #
##############################################################
include_directories(${SRC_TOP_DIR}/upf_app/kernel/xdp)
include_directories(${SRC_TOP_DIR}/upf_app/app)

set(GTP_INTERFACE $ENV{GTP_INTERFACE})
set(UDP_INTERFACE $ENV{UDP_INTERFACE})
set(SOCKET_BUFFER_ENABLED $ENV{SOCKET_BUFFER_ENABLED})

add_library(UPF_XDP STATIC
  UserPlaneComponent.cpp
  Configuration.cpp
  SignalHandler.cpp
  helpers/NextHopFinder.cpp
  helpers/CmdRunner.cpp
  helpers/SdfFilterParser.cpp
  SessionProgramManager.cpp
  SessionManager.cpp
  SessionPrograms.cpp
  user/pfcp_session_lookup_xdp_user.cpp
  user/BPFProgram.cpp
  user/wrappers/BPFMaps.cpp
  user/wrappers/BPFMap.cpp
  user/utils/bpf_utils.cpp
  user/utils/net_utils.cpp
)

link_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../build/ext/libbpf/src)
target_link_libraries(UPF_XDP
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../build/ext/libbpf/src/libbpf.a
  ${CMAKE_CURRENT_SOURCE_DIR}/../../build/ext/libbpf/src/libbpf.so
  PRIVATE elf
  PRIVATE z qer_tc
)

target_include_directories(UPF_XDP PUBLIC
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/include>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/kernel>
  #$<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/skel>
  $<BUILD_INTERFACE:${OPENAIRCN_DIR}/build/upf/build/skel>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/user>
  
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


##############################################################
#                          QER                               #
##############################################################
  include_directories(${SRC_TOP_DIR}/upf_app/kernel/tc)

  add_library(UPF_TC STATIC
  UserPlaneComponent.cpp
  Configuration.cpp
  SignalHandler.cpp
  helpers/NextHopFinder.cpp
  helpers/SdfFilterParser.cpp
  helpers/GetNicInformation.cpp
  SessionProgramManager.cpp
  SessionManager.cpp
  SessionPrograms.cpp
  user/qer_tc_user.cpp
  user/BPFProgram.cpp
  user/wrappers/BPFMaps.cpp
  user/wrappers/BPFMap.cpp
  user/utils/bpf_utils.cpp
  user/utils/net_utils.cpp
)

  target_link_libraries(UPF_TC
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../build/ext/libbpf/src/libbpf.a
  ${CMAKE_CURRENT_SOURCE_DIR}/../../build/ext/libbpf/src/libbpf.so.1
  PRIVATE elf
  PRIVATE z
  libnl-3.so
  libnl-route-3.so
)

  target_include_directories(UPF_TC PUBLIC
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/include>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/kernel>
  #$<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/skel>
  $<BUILD_INTERFACE:${OPENAIRCN_DIR}/build/upf/build/skel>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/user>
  )

  add_dependencies(UPF_TC upf_xdp_all)

  add_dependencies(UPF_TC upf_tc_all)

  install(
      TARGETS UPF_TC
      EXPORT "${TARGETS_EXPORT_NAME}"
      LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
      ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
      RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
      INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  )

