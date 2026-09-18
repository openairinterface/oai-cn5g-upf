# SPDX-License-Identifier: LicenseRef-CSSL-1.0
#
# SIMPLE_SWITCH -- userspace (non-eBPF) datapath and the PFCP rule model
#                  (PDR/FAR/QER/URR/BAR/MAR) shared with the eBPF path.

# -----------------------------------------------------------------------------
# Framed routing sources -- location depends on which branches are merged.
#
# On develop they live in src/upf_app/framed_routing/, and the legacy list file
# reached across for them by absolute path:
#     ${SRC_TOP_DIR}/upf_app/framed_routing/FramedRouting.cpp
#     ${SRC_TOP_DIR}/upf_app/framed_routing/LocalRouting.cpp
# while src/upf_app/framed_routing/CMakeLists.txt separately declared an unused
# FRAMED_ROUTING library over the same two files.
#
# feature-framed-routing moves both into this directory. Detecting the layout
# means this file works either way, so the CMake work and the framed-routing
# work can land in either order. Delete the else() branch once the move lands.
# -----------------------------------------------------------------------------
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/FramedRouting.cpp")
  set(SIMPLE_SWITCH_FRAMED_ROUTING_SOURCES
    FramedRouting.cpp
    LocalRouting.cpp)
else()
  set(SIMPLE_SWITCH_FRAMED_ROUTING_SOURCES
    "${UPF_APP_DIR}/framed_routing/FramedRouting.cpp"
    "${UPF_APP_DIR}/framed_routing/LocalRouting.cpp")
  # Pre-move, FramedRouting.hpp is included as "framed_routing/FramedRouting.hpp"
  # by pfcp_pdr.hpp / pfcp_session.hpp / pfcp_switch.hpp, so the PARENT of that
  # directory has to be on the include path.
  list(APPEND SIMPLE_SWITCH_EXTRA_INCLUDES
    "${UPF_APP_DIR}"
    "${UPF_APP_DIR}/framed_routing")
endif()

add_library(SIMPLE_SWITCH STATIC
  pfcp_bar.cpp
  pfcp_far.cpp
  pfcp_mar.cpp
  pfcp_pdr.cpp
  pfcp_qer.cpp
  pfcp_session.cpp
  pfcp_urr.cpp
  pfcp_switch.cpp
  simple_switch.cpp
  ${SIMPLE_SWITCH_FRAMED_ROUTING_SOURCES})

target_include_directories(SIMPLE_SWITCH PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}")

target_include_directories(SIMPLE_SWITCH PRIVATE
  ${SIMPLE_SWITCH_EXTRA_INCLUDES}
  "${SRC_TOP_DIR}/oai_upf"
  "${SRC_TOP_DIR}/pfcp"
  "${SRC_TOP_DIR}/udp"
  "${UPF_APP_DIR}"
  "${UPF_APP_DIR}/app"
  "${UPF_APP_DIR}/control"
  "${UPF_APP_DIR}/include")

# upf::kernel_headers replaces the commented-out
#   #include_directories(${SRC_TOP_DIR}/upf_app/kernel/include)
# and its uncommented twin on feature-framed-routing. FramedRouting.cpp needs
# framed_routing_bpf.h from kernel/include so the userspace key derivation and
# the XDP helper stay in sync -- it is a real dependency and is declared as one.
target_link_libraries(SIMPLE_SWITCH
  PUBLIC  upf::core oai::common
  PRIVATE upf::kernel_headers GTPV1U PFCP UDP fmt::fmt)
