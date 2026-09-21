# SPDX-License-Identifier: LicenseRef-CSSL-1.0
#
# upf_paths.cmake -- single source of truth for every out-of-tree path.
#
# WHY THIS FILE EXISTS
# --------------------
# The legacy build spelled the same external directory three different ways:
#
#   ${SRC_TOP_DIR}/../build/ext/libbpf/root/usr/include
#   ${CMAKE_CURRENT_SOURCE_DIR}/../../build/ext/libbpf/src/libbpf.a
#   ${OPENAIRCN_DIR}/build/upf/build/skel
#
# The first two escape their own directory with `..`, so their meaning depends
# on which CMakeLists happens to be executing -- and `src/oai_upf/CMakeLists.txt`
# is pulled in with include() rather than add_subdirectory(), meaning
# CMAKE_CURRENT_SOURCE_DIR there is build/upf, NOT src/oai_upf. Relative paths
# in that file resolve somewhere other than where they appear to.
#
# Every path below is absolute and anchored on OPENAIRCN_DIR. No `..` anywhere.
# Include this once from the top-level list file; the variables then propagate
# to every add_subdirectory() scope.

if(DEFINED _UPF_PATHS_INCLUDED)
  return()
endif()
set(_UPF_PATHS_INCLUDED TRUE)

if(NOT DEFINED OPENAIRCN_DIR OR OPENAIRCN_DIR STREQUAL "")
  message(FATAL_ERROR
    "OPENAIRCN_DIR is not set. It is exported by build/scripts/build_upf and "
    "read via $ENV{OPENAIRCN_DIR} in the top-level CMakeLists.txt.")
endif()

get_filename_component(OPENAIRCN_DIR "${OPENAIRCN_DIR}" ABSOLUTE)

# --- Source and build roots --------------------------------------------------
set(SRC_TOP_DIR   "${OPENAIRCN_DIR}/src"   CACHE INTERNAL "UPF source root")
set(BUILD_TOP_DIR "${OPENAIRCN_DIR}/build" CACHE INTERNAL "UPF build root")

# common-src is a git submodule mounted under src/. MOUNTED_COMMON holds its
# directory name so the tree can be relocated without touching every list file.
set(COMMON_SRC_DIR "${SRC_TOP_DIR}/${MOUNTED_COMMON}" CACHE INTERNAL
    "OAI common-src submodule root")

# --- libbpf (built out-of-tree by build/scripts/build_helper.upf) ------------
# `make install_headers DESTDIR=.../root PREFIX=/usr` puts bpf/*.h under root/,
# while the compiled libbpf.a / libbpf.so stay in src/.
set(LIBBPF_ROOT        "${BUILD_TOP_DIR}/ext/libbpf"            CACHE INTERNAL "")
set(LIBBPF_INCLUDE_DIR "${LIBBPF_ROOT}/root/usr/include"        CACHE INTERNAL "")
set(LIBBPF_LIB_DIR     "${LIBBPF_ROOT}/src"                     CACHE INTERNAL "")

# --- Generated BPF skeleton headers ------------------------------------------
# `bpftool gen skeleton` output, consumed by the user/*_user.cpp wrappers.
#
# Lives in the BUILD tree, not the source tree. Legacy hardcoded
# ${OPENAIRCN_DIR}/build/upf/build/skel, which is the binary directory of the
# standard build_upf invocation -- fine for that one case, but it means any
# other build directory still writes its generated headers back into the repo.
# Two build trees then share one skel/ and overwrite each other's output, and a
# build directory owned by another user (a previous sudo build, say) fails with
#   /bin/sh: cannot create .../skel/xdp_bar_apply_skel.h: Permission denied
# CMAKE_BINARY_DIR resolves to exactly the same path for the normal build_upf
# flow, so nothing changes there -- it just stops out-of-source builds from
# reaching into the source tree.
set(UPF_SKEL_DIR "${CMAKE_BINARY_DIR}/skel" CACHE INTERNAL
    "Generated libbpf skeleton headers")

# --- Compiled BPF objects ----------------------------------------------------
# Kept at a fixed, predictable location rather than buried in a per-directory
# CMakeFiles/<target>.dir/ path. qer_tc_kern.c.o is a *runtime* artifact: the TC
# datapath loads it with `tc filter add ... bpf obj <file>`, so it is shipped in
# the container image and docker/Dockerfile.upf.ubuntu copies it out of the
# builder stage by path. The legacy location
#   build/upf/build/upf_app/kernel/CMakeFiles/qer_tc.dir/tc/qer_tc_kern.c.o
# was an artefact of add_library() and moved as soon as the BPF objects stopped
# going through CMake's compiler driver.
set(UPF_BPF_OBJ_DIR "${CMAKE_BINARY_DIR}/bpf" CACHE INTERNAL
    "Compiled BPF object files")

# --- upf_app subsystem roots -------------------------------------------------
set(UPF_APP_DIR    "${SRC_TOP_DIR}/upf_app"        CACHE INTERNAL "")
set(UPF_KERNEL_DIR "${UPF_APP_DIR}/kernel"         CACHE INTERNAL "")
set(UPF_CMAKE_DIR  "${UPF_APP_DIR}/cmake"          CACHE INTERNAL "")

# -----------------------------------------------------------------------------
# libbpf::bpf -- imported target replacing the hand-written absolute paths.
#
# The legacy build linked BOTH the static and the shared libbpf into the same
# target (libbpf.a + libbpf.so for UPF_XDP, libbpf.a + libbpf.so.1 for UPF_TC),
# which is never correct: duplicate symbol definitions, and which one wins is
# left to link order. We link the static archive only, and carry the include
# directory and the system deps (elf, z) as usage requirements so no consumer
# has to repeat them.
# -----------------------------------------------------------------------------
# Fail early and legibly if libbpf has not been built yet.
#
# An IMPORTED target whose INTERFACE_INCLUDE_DIRECTORIES points at a missing
# directory makes CMake abort at GENERATE time with
#   "Imported target libbpf::bpf includes non-existent path ..."
# which says nothing about how to fix it. libbpf is an out-of-tree dependency
# built by build/scripts/build_helper.upf, and a `build_upf` run that
# re-installs external dependencies re-clones it -- leaving the headers absent
# until the build step finishes.
if(NOT EXISTS "${LIBBPF_INCLUDE_DIR}" OR NOT EXISTS "${LIBBPF_LIB_DIR}/libbpf.a")
  message(FATAL_ERROR
    "libbpf is not built.\n"
    "  expected headers : ${LIBBPF_INCLUDE_DIR}\n"
    "  expected archive : ${LIBBPF_LIB_DIR}/libbpf.a\n"
    "Build it first with:  ./build/scripts/build_upf --install-deps\n"
    "(build_helper.upf clones libbpf into ${LIBBPF_ROOT}, runs make, then\n"
    " `make install_headers DESTDIR=${LIBBPF_ROOT}/root PREFIX=/usr`.)")
endif()

if(NOT TARGET libbpf::bpf)
  add_library(libbpf::bpf STATIC IMPORTED GLOBAL)
  set_target_properties(libbpf::bpf PROPERTIES
    IMPORTED_LOCATION             "${LIBBPF_LIB_DIR}/libbpf.a"
    INTERFACE_INCLUDE_DIRECTORIES "${LIBBPF_INCLUDE_DIR}"
    INTERFACE_LINK_LIBRARIES      "elf;z")
endif()

# -----------------------------------------------------------------------------
# INTERFACE targets carrying include directories as usage requirements.
#
# The legacy build called directory-scoped include_directories() roughly 120
# times across 11 list files. That command applies to every target created in
# the current directory AND every directory added below it, so each subsystem
# inherited the include paths of every other subsystem. Nothing declared what it
# actually depended on, and a missing #include path in one library was masked by
# an unrelated library having added it earlier.
#
# These INTERFACE targets carry the same paths as usage requirements instead:
# a target that links oai::common gets those directories, and one that does not,
# does not. Dependencies become explicit and the compiler catches missing ones.
# -----------------------------------------------------------------------------

# OAI common-src submodule -- shared by every UPF subsystem.
if(NOT TARGET oai::common)
  add_library(oai_common_includes INTERFACE)
  add_library(oai::common ALIAS oai_common_includes)
  target_include_directories(oai_common_includes INTERFACE
    "${COMMON_SRC_DIR}/3gpp"
    "${COMMON_SRC_DIR}/common"
    "${COMMON_SRC_DIR}/config"
    "${COMMON_SRC_DIR}/http"
    "${COMMON_SRC_DIR}/logger"
    "${COMMON_SRC_DIR}/model"
    "${COMMON_SRC_DIR}/pfcp"
    "${COMMON_SRC_DIR}/utils"
    "${COMMON_SRC_DIR}/utils/bstr")
endif()

# UPF-local shared headers (src/common, src/itti, …) used across subsystems.
if(NOT TARGET upf::core)
  add_library(upf_core_includes INTERFACE)
  add_library(upf::core ALIAS upf_core_includes)
  target_include_directories(upf_core_includes INTERFACE
    "${SRC_TOP_DIR}/common"
    "${SRC_TOP_DIR}/common/msg"
    "${SRC_TOP_DIR}/common/utils"
    "${SRC_TOP_DIR}/itti")
endif()

# Kernel-side BPF headers, shared between the BPF objects themselves and the
# user-space wrappers that include the same struct definitions.
if(NOT TARGET upf::kernel_headers)
  add_library(upf_kernel_includes INTERFACE)
  add_library(upf::kernel_headers ALIAS upf_kernel_includes)
  target_include_directories(upf_kernel_includes INTERFACE
    "${UPF_APP_DIR}"
    "${UPF_APP_DIR}/include"
    "${UPF_KERNEL_DIR}"
    "${UPF_KERNEL_DIR}/include"
    "${UPF_KERNEL_DIR}/pfcp"
    "${UPF_KERNEL_DIR}/pfcp/ie"
    "${UPF_KERNEL_DIR}/xdp"
    "${UPF_KERNEL_DIR}/tc")
endif()
