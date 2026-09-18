# SPDX-License-Identifier: LicenseRef-CSSL-1.0
#
# DEAD FILE -- recommended action: delete src/upf_app/framed_routing/CMakeLists.txt
#
# This file declares a FRAMED_ROUTING static library that is never built and
# never linked:
#
#   * No add_subdirectory(${SRC_TOP_DIR}/upf_app/framed_routing) exists anywhere.
#   * `FRAMED_ROUTING` appears in no target_link_libraries() call.
#   * simpleswitch/CMakeLists.txt compiles the same two sources directly, by
#     absolute path, into SIMPLE_SWITCH:
#         ${SRC_TOP_DIR}/upf_app/framed_routing/FramedRouting.cpp
#         ${SRC_TOP_DIR}/upf_app/framed_routing/LocalRouting.cpp
#
# It also lists a header (LocalRouting.hpp) in add_library() sources, which is
# harmless but misleading -- headers belong in target_sources(FILE_SET HEADERS)
# or nowhere at all.
#
# NOTE FOR THE FRAMED-ROUTING BRANCH
# ----------------------------------
# feature-framed-routing moves FramedRouting.{cpp,hpp}, LocalRouting.{cpp,hpp}
# and FramedRoutingHash.h into src/upf_app/simpleswitch/ and drops the
# upf_app/framed_routing include directory from all three list files. Once that
# branch merges, this directory is empty and both it and this file should go.
#
# -- intentionally empty --
