# SPDX-License-Identifier: LicenseRef-CSSL-1.0
#
# APP -- UPF application layer: NRF registration, N4 session handling,
#        YAML configuration, PFCP association.

add_library(APP STATIC
  upf_app.cpp
  upf_config.cpp
  upf_config_yaml.cpp
  upf_n4.cpp
  upf_nrf.cpp
  upf_pfcp_association.cpp
  upf_profile.cpp)

target_include_directories(APP PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}")

# Consumed by this target's own sources only.
target_include_directories(APP PRIVATE
  "${SRC_TOP_DIR}/oai_upf"
  "${SRC_TOP_DIR}/pfcp"
  "${SRC_TOP_DIR}/udp"
  "${UPF_APP_DIR}"
  "${UPF_APP_DIR}/control"
  "${UPF_APP_DIR}/include"
  "${UPF_APP_DIR}/simpleswitch")

target_link_libraries(APP
  PUBLIC  upf::core oai::common
  PRIVATE upf::kernel_headers GTPV1U PFCP UDP)

# PACKAGE_NAME was set here with add_definitions(), which applies to every
# target in this directory and all directories below it. As a target property it
# reaches APP and nothing else. (src/oai_upf also set the identical definition --
# the duplicate is dropped.)
target_compile_definitions(APP PRIVATE PACKAGE_NAME="UPF")
