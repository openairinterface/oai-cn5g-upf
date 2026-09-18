# SPDX-License-Identifier: LicenseRef-CSSL-1.0
#
# UDP -- UDP socket server used by the PFCP N4 endpoint.

add_library(UDP STATIC
  udp.cpp)

target_include_directories(UDP PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}")

# PFCP headers are needed by udp.cpp itself, not by UDP's consumers -> PRIVATE.
target_include_directories(UDP PRIVATE
  "${SRC_TOP_DIR}/pfcp")

target_link_libraries(UDP PUBLIC upf::core oai::common)
