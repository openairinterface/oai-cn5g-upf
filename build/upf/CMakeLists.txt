# SPDX-License-Identifier: LicenseRef-CSSL-1.0
#
# Top-level list file for the OAI UPF.
#
# Invoked by build/scripts/build_upf, which exports OPENAIRCN_DIR and runs
# cmake from this directory.

# 3.18 is the floor: find_library(... REQUIRED) below needs it.
# Ubuntu 22.04 ships 3.22, so this is comfortably satisfied.
cmake_minimum_required(VERSION 3.18)

# LANGUAGES is explicit: the default (C CXX) is what we want, but stating it
# stops CMake probing for compilers we never use.
project(oai-upf
  VERSION     1.0.0
  DESCRIPTION "OpenAirInterface 5G User Plane Function (eBPF/XDP datapath)"
  LANGUAGES   C CXX)

# -----------------------------------------------------------------------------
# Language standard
#
# Legacy build hand-wrote `-std=c++17` into four separate per-configuration flag
# strings (CMAKE_CXX_FLAGS_DEBUG / _RELEASE / _RELWITHDEBINFO / _MINSIZEREL), so
# any configuration added later silently compiled as the compiler default.
# These three lines cover every configuration, current and future.
# -----------------------------------------------------------------------------
set(CMAKE_C_STANDARD           99)
set(CMAKE_C_STANDARD_REQUIRED  ON)
set(CMAKE_CXX_STANDARD         17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Extensions stay ON (-std=gnu++17), matching the legacy build.
#
# Not a style choice: with them OFF (-std=c++17) glibc hides the POSIX
# declarations, and src/upf_app/utils/startup_banner.cpp calls sleep() without
# including <unistd.h>, so the build fails with "'sleep' was not declared".
# Several sources lean on GNU extensions this way.
#
# Follow-up, as a source change rather than a build one: add the missing POSIX
# includes, then flip this to OFF.
set(CMAKE_CXX_EXTENSIONS       ON)

# Position-independent code for every target, replacing the `-fPIC` that the
# legacy CMAKE_C_FLAGS carried until line 140 of src/oai_upf/CMakeLists.txt
# overwrote the variable wholesale.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Default build type. The legacy tree set this in three different places, one of
# which (cmake/toolchain.cmake) forced Release unconditionally and silently
# discarded whatever the operator asked for.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Build type" FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
               Debug Release RelWithDebInfo MinSizeRel)
endif()
message(STATUS "Build type    : ${CMAKE_BUILD_TYPE}")
message(STATUS "Architecture  : ${CMAKE_SYSTEM_PROCESSOR}")

# -----------------------------------------------------------------------------
# Base directories, compatible with legacy OAI naming
# -----------------------------------------------------------------------------
set(PACKAGE_NAME     "UPF")
set(NF_TARGET        upf)
set(MOUNTED_COMMON   common-src)
set(OPENAIRCN_DIR    "$ENV{OPENAIRCN_DIR}")

option(STATIC_LINKING "Build a fully statically linked binary" OFF)

# Resolves OPENAIRCN_DIR, derives every other path from it, and defines the
# libbpf::bpf imported target. Must run before any add_subdirectory().
include(${OPENAIRCN_DIR}/src/upf_app/cmake/upf_paths.cmake)

# Only the UPF's own module directory.
#
# The legacy build also put ${BUILD_TOP_DIR}/cmake_modules on this path. That
# directory holds ~20 vendored find-modules inherited from the OAI monorepo
# (MySQL, Bison, Flex, FreeDiameter, GCCXML, Kbuild, …), none of which this
# project uses -- but CMAKE_MODULE_PATH is searched BEFORE CMake's own modules,
# so build/cmake_modules/FindThreads.cmake silently replaced the builtin
# FindThreads. The vendored copy predates imported targets and defines no
# Threads::Threads, so anything linking it fails to resolve. The legacy build
# never noticed because it linked the bare name `pthread`.
#
# If any of those modules is ever genuinely needed, add that one file to
# src/upf_app/cmake/ rather than putting the whole directory on the path.
list(APPEND CMAKE_MODULE_PATH "${UPF_CMAKE_DIR}")

# -----------------------------------------------------------------------------
# The UPF source tree
#
# add_subdirectory(), not include(). The legacy build used
#   include(${CMAKE_CURRENT_SOURCE_DIR}/../../src/oai_upf/CMakeLists.txt)
# which executes that file in THIS directory's scope, so every
# CMAKE_CURRENT_SOURCE_DIR reference inside it silently pointed at build/upf
# instead of src/oai_upf. add_subdirectory() gives it its own scope and makes
# relative paths mean what they look like they mean.
# -----------------------------------------------------------------------------
# Binary directory is deliberately NOT named "oai_upf": all three Dockerfiles do
#   mv /openair-upf/build/upf/build/upf /openair-upf/build/upf/build/oai_upf
# to rename the executable. If a directory of that name already exists there,
# mv silently moves the binary *into* it and the later COPY grabs a directory
# instead of the executable -- a broken image with no error at build time.
add_subdirectory(${SRC_TOP_DIR}/oai_upf ${CMAKE_CURRENT_BINARY_DIR}/src_oai_upf)
