# SPDX-License-Identifier: LicenseRef-CSSL-1.0
#
# PFCP -- PFCP protocol layer.
#
# Note: this target compiles 3gpp_29.244.cpp out of the common-src submodule.
# That file belongs to common-src, and pulling a sibling module's source into
# this target is a layering violation -- common-src should expose it as its own
# library. Kept as-is here to avoid changing what gets built; flagged for a
# follow-up.

add_library(PFCP STATIC
  "${CMAKE_CURRENT_SOURCE_DIR}/pfcp.cpp"
  "${COMMON_SRC_DIR}/pfcp/3gpp_29.244.cpp")

target_include_directories(PFCP PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}")

target_include_directories(PFCP PRIVATE
  "${SRC_TOP_DIR}/udp")

target_link_libraries(PFCP PUBLIC upf::core oai::common)
