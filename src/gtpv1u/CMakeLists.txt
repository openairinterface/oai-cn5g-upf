# SPDX-License-Identifier: LicenseRef-CSSL-1.0
#
# GTPV1U -- GTP-U (3GPP TS 29.281) encoding/decoding.

add_library(GTPV1U STATIC
  3gpp_29.281.cpp
  gtpv1u.cpp)

target_include_directories(GTPV1U PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}")

target_include_directories(GTPV1U PRIVATE
  "${SRC_TOP_DIR}/udp")

target_link_libraries(GTPV1U PUBLIC upf::core oai::common)
