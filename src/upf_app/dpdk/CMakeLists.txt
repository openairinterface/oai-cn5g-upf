# SPDX-License-Identifier: LicenseRef-CSSL-1.0

# ==========================================================================
# UPF_DPDK — DPDK poll-mode datapath library (built only with -DWITH_DPDK=ON)
#
# Control-plane pieces shared with the eBPF flavour (SessionManager,
# Configuration, helpers) are compiled in UPF_XDP; this library only holds
# the DPDK-specific code and resolves against them at final link time.
# ==========================================================================

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBDPDK REQUIRED IMPORTED_TARGET libdpdk)
message(STATUS "DPDK datapath enabled (libdpdk ${LIBDPDK_VERSION})")

include_directories(${SRC_TOP_DIR}/common)
include_directories(${SRC_TOP_DIR}/common/msg)
include_directories(${SRC_TOP_DIR}/common/utils)
include_directories(${SRC_TOP_DIR}/itti)
include_directories(${SRC_TOP_DIR}/pfcp)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/3gpp)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/common)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/config)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/pfcp)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils/bstr)
include_directories(${SRC_TOP_DIR}/upf_app)
include_directories(${SRC_TOP_DIR}/upf_app/app)
include_directories(${SRC_TOP_DIR}/upf_app/control)
include_directories(${SRC_TOP_DIR}/upf_app/include)
include_directories(${SRC_TOP_DIR}/upf_app/simpleswitch)
include_directories(${SRC_TOP_DIR}/upf_app/framed_routing)
# Shared rule structs (kernel/pfcp/*.h) used by the fast-path tables
include_directories(${SRC_TOP_DIR}/upf_app/kernel)
include_directories(${SRC_TOP_DIR}/upf_app/kernel/include)
include_directories(${SRC_TOP_DIR}/upf_app/kernel/pfcp)
include_directories(${SRC_TOP_DIR}/upf_app/kernel/pfcp/ie)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/nrf_model.cmake)

add_library(UPF_DPDK STATIC
  DpdkDatapath.cpp
  DpdkEal.cpp
  DpdkFastPath.cpp
  DpdkPipeline.cpp
  DpdkPort.cpp
  DpdkSessionStore.cpp
  DpdkSessionTables.cpp
  DpdkWorker.cpp
)

# The static inline helpers in the DPDK headers need the baseline the library
# was built for.
target_compile_options(UPF_DPDK PRIVATE ${LIBDPDK_CFLAGS_OTHER})

target_include_directories(UPF_DPDK PUBLIC
  $<BUILD_INTERFACE:${SRC_TOP_DIR}/upf_app/dpdk>
)

target_link_libraries(UPF_DPDK PUBLIC PkgConfig::LIBDPDK)
