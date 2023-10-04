include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/toolchain.cmake)
add_subdirectory(bpf)
include_directories(${SRC_TOP_DIR}/upf_app/bpf/bpf_pfcp)
include_directories(${SRC_TOP_DIR}/upf_app/simpleswitch)
include_directories(${SRC_TOP_DIR}/common)
include_directories(${SRC_TOP_DIR}/common/msg)
include_directories(${SRC_TOP_DIR}/common/utils)
include_directories(${SRC_TOP_DIR}/gtpv1u)
include_directories(${SRC_TOP_DIR}/itti)
include_directories(${SRC_TOP_DIR}/udp)  
include_directories(${SRC_TOP_DIR}/pfcp)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/config)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils/utils.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/nrf/nrf_model.cmake)

include_directories(${SRC_TOP_DIR}/upf_app/bpf)
include_directories(${SRC_TOP_DIR}/upf_app/app)

set(GTP_INTERFACE $ENV{GTP_INTERFACE})
set(UDP_INTERFACE $ENV{UDP_INTERFACE})
set(SOCKET_BUFFER_ENABLED $ENV{SOCKET_BUFFER_ENABLED})

add_library(UPF_XDP STATIC
  UserPlaneComponent.cpp
  Configuration.cpp
  SignalHandler.cpp
  NextHopFinder.cpp
  SessionProgramManager.cpp
  SessionManager.cpp
  SessionPrograms.cpp
  programs/pfcp_session_pdr_lookup_ebpf_xdp_prgrm_user.cpp
  programs/pfcp_session_lookup_ebpf_xdp_prgrm_user.cpp
  programs/far_ebpf_xdp_prgrm_user.cpp
  programs/BPFProgram.cpp
  wrappers/BPFMaps.cpp
  wrappers/BPFMap.cpp
  # utils/Logger.cpp
  # utils/Util.cpp
  # utils/NextProgRuleKey.cpp
)

link_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../build/ext/libbpf/src)
target_link_libraries(UPF_XDP
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../build/ext/libbpf/src/libbpf.a
  ${CMAKE_CURRENT_SOURCE_DIR}/../../build/ext/libbpf/src/libbpf.so
  # PUBLIC upfutils
  # PRIVATE spdlog
  PRIVATE elf
  PRIVATE z
)

target_include_directories(UPF_XDP PUBLIC
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/include>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/bpf>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/skel>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/interfaces>
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/programs>
)

add_dependencies(UPF_XDP upf_ebpf_xdp_all)

# configure_file (
#     ${PROJECT_SOURCE_DIR}/cmake/Configuration.h.in
#     ${PROJECT_SOURCE_DIR}/src/Configuration.h
# )

# configure_file (
#     ${PROJECT_SOURCE_DIR}/cmake/Configuration.cpp.in
#     ${PROJECT_SOURCE_DIR}/src/Configuration.cpp
# )

# Targets:
#   * <prefix>/lib/upf_bpf.a
#   * header location after install: <prefix>/include/*.h
#   * headers can be included by C++ code `#include <*/*.h>`
install(
    TARGETS UPF_XDP
    EXPORT "${TARGETS_EXPORT_NAME}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

# Headers:
#   * ./*.h -> <prefix>/include/*.h
# install(
#     DIRECTORY "./"
#     DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
#     FILES_MATCHING PATTERN "*.h"
# )
