# SPDX-License-Identifier: LicenseRef-CSSL-1.0
#
# DEAD FILE -- recommended action: delete src/common/CMakeLists.txt
#
# Two independent reasons it never does anything:
#
#   1. Nothing adds this directory. Grepping every add_subdirectory() in the
#      tree yields src/common/utils, src/pfcp, src/upf_app, src/upf_app/app,
#      src/upf_app/simpleswitch, src/gtpv1u and src/udp -- never src/common
#      itself. This file is never parsed.
#
#   2. Even if it were, `add_library(3GPP_COMMON_TYPES STATIC)` declares a
#      target with no sources, which CMake rejects with
#      "No SOURCES given to target".
#
# The headers in src/common/ are still used -- they are picked up through the
# include path (see upf::core in cmake/upf_paths.cmake), which is the correct
# mechanism for a header-only directory. No library target is needed.
#
# If a target is ever genuinely wanted here, it should be an INTERFACE library:
#
#   add_library(3GPP_COMMON_TYPES INTERFACE)
#   target_include_directories(3GPP_COMMON_TYPES INTERFACE
#     "${CMAKE_CURRENT_SOURCE_DIR}"
#     "${CMAKE_CURRENT_SOURCE_DIR}/msg")
#   target_link_libraries(3GPP_COMMON_TYPES INTERFACE oai::common)
#
# -- intentionally empty --
