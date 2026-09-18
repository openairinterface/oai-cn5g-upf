# SPDX-License-Identifier: LicenseRef-CSSL-1.0
#
# bpf_flags.cmake -- compile settings for BPF object targets ONLY.
#
# NOTE: despite the filename this is NOT a CMAKE_TOOLCHAIN_FILE. The name is
# retained only so the diff against the previous file stays readable; it should
# be renamed bpf_flags.cmake. The previous version is kept as toolchain.old.cmake.
#
# WHY THE LEGACY FILE WAS WRONG
# -----------------------------
# cmake/toolchain.cmake is named like a CMAKE_TOOLCHAIN_FILE but is never used
# as one. It is include()d into ordinary directory scope from two places --
# src/upf_app/CMakeLists.txt:3 and src/upf_app/kernel/CMakeLists.txt:3 -- long
# after project() has run. Consequences:
#
#   set(CMAKE_SYSTEM_NAME Linux)        -- meaningless outside a toolchain file.
#   set(CMAKE_C_COMPILER clang)         -- ignored; the compiler is locked in by
#   set(CMAKE_CXX_COMPILER clang++)        project(), which already ran.
#   set(CMAKE_BUILD_TYPE Release)       -- silently overrides the operator's
#                                          choice from src/oai_upf's
#                                          add_list_string_option(CMAKE_BUILD_TYPE …).
#   set(CMAKE_CXX_COMPILER_TARGET bpf)  -- retargets HOST C++ at the BPF triple;
#   CMAKE_C_FLAGS "… -target bpf …"        it leaks to every C/C++ target in the
#                                          upf_app/ subtree, not just kernel/.
#
# The BPF triple must apply to the .o files fed to `bpftool gen skeleton` and to
# nothing else. Below it is a per-target property, applied by
# upf_set_bpf_target_properties(), so it cannot leak into host code.

if(DEFINED _UPF_BPF_FLAGS_INCLUDED)
  return()
endif()
set(_UPF_BPF_FLAGS_INCLUDED TRUE)

# clang is required for BPF codegen; gcc cannot emit the bpf target.
find_program(UPF_BPF_CLANG NAMES clang
             DOC "clang used to compile eBPF objects")
if(NOT UPF_BPF_CLANG)
  message(FATAL_ERROR "clang not found -- required to compile eBPF objects.")
endif()

find_program(UPF_BPFTOOL NAMES bpftool
             HINTS "${BUILD_TOP_DIR}/ext/bpftool/src"
             DOC "bpftool used to generate libbpf skeletons")
if(NOT UPF_BPFTOOL)
  message(FATAL_ERROR
    "bpftool not found -- built by build/scripts/build_helper.upf.")
endif()

find_program(UPF_LLVM_OBJCOPY NAMES llvm-objcopy)
find_program(UPF_LLVM_STRIP   NAMES llvm-strip)

# -----------------------------------------------------------------------------
# BPF compile settings.
#
# Exposed as plain lists rather than target properties: the BPF objects are not
# built by CMake's compiler driver at all (see kernel/CMakeLists.txt -- they are
# produced by an explicit clang invocation), so there is no target to hang
# properties on until after the object already exists.
# -----------------------------------------------------------------------------

# -O2 is not a preference: the BPF verifier rejects unoptimised output, so it
# applies regardless of CMAKE_BUILD_TYPE. -g emits the BTF that
# `bpftool gen skeleton` needs.
set(UPF_BPF_CFLAGS
  -target bpf
  -O2
  -g
  -Wall
  -Qunused-arguments
  # libbpf map definitions end in a flexible array member; noise for BPF.
  -Wno-gnu-variable-sized-type-not-at-end
  -DKERNEL_SPACE)

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
  list(APPEND UPF_BPF_CFLAGS -D__TARGET_ARCH_x86)
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
  list(APPEND UPF_BPF_CFLAGS -D__TARGET_ARCH_arm64)
endif()

if(BPF_DEBUG)
  list(APPEND UPF_BPF_CFLAGS -DBPF_DEBUG)
endif()
