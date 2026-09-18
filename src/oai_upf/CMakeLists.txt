# SPDX-License-Identifier: LicenseRef-CSSL-1.0
#
# The `upf` executable, and the dependency/option plumbing for the whole tree.
#
# In the legacy build this file also carried project(), cmake_minimum_required()
# and all global compile flags, because build/upf/CMakeLists.txt pulled it in
# with include() rather than add_subdirectory(). Those now live in the top-level
# list file where they belong; this file defines the executable and nothing that
# leaks upward.

# -----------------------------------------------------------------------------
# Options
#
# The legacy tree carried six add_*_option macros (~70 lines). Only
# add_boolean_option and add_list_string_option were ever called; add_option,
# add_integer_option, add_list1_option and add_list2_option were dead.
#
# All four surviving call sites are replaced by option()/set(CACHE) plus
# target_compile_definitions. The macros used add_definitions(), which applies
# to every target in scope and below, so a flag meant for the logger reached the
# BPF objects too.
# -----------------------------------------------------------------------------
option(DISPLAY_LICENCE_INFO "Show a module's licence banner at startup" OFF)
option(USE_LTTNG            "Enable the LTTng tracer"                   OFF)
option(LOG_OAI              "Thread-safe logging API"                   ON)
option(LOG_OAI_MINIMAL      "Log only levels above NOTICE"              OFF)

# LOG_OAI/LOG_OAI_MINIMAL were set three times with conflicting values --
# True at :107-108 and :111 depending on build type, then False again at
# :229. Because add_boolean_option() writes to the CACHE, the first call wins
# and the later one still emits a contradictory -DLOG_OAI=0. The intent was
# "minimal logging in RelWithDebInfo", expressed directly:
if(CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo" AND NOT DEFINED CACHE{LOG_OAI_MINIMAL})
  set(LOG_OAI_MINIMAL ON CACHE BOOL "" FORCE)
endif()

# -----------------------------------------------------------------------------
# Dependencies
#
# Each is located once, here, and consumed through an imported target.
# -----------------------------------------------------------------------------
find_package(PkgConfig REQUIRED)
pkg_search_module(CONFIGXX REQUIRED IMPORTED_TARGET libconfig++)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
find_package(cpr     REQUIRED)
find_package(fmt     REQUIRED)
find_package(spdlog  REQUIRED)
find_package(yaml-cpp REQUIRED)


# These were linked by bare name with no search at all -- `gflags glog dl
# double-conversion folly boost_system event curl`. A bare name is handed
# straight to the linker, so a missing library surfaces as an unresolved symbol
# at link time instead of a clear configure-time error.
find_library(GFLAGS_LIBRARY   NAMES gflags            REQUIRED)
find_library(GLOG_LIBRARY     NAMES glog              REQUIRED)
find_library(DOUBLECONV_LIBRARY NAMES double-conversion REQUIRED)
find_library(FOLLY_LIBRARY    NAMES folly             REQUIRED)
find_library(EVENT_LIBRARY    NAMES event             REQUIRED)
find_library(BOOST_SYSTEM_LIBRARY NAMES boost_system  REQUIRED)
find_package(CURL REQUIRED)

# -----------------------------------------------------------------------------
# Subsystems
# -----------------------------------------------------------------------------
add_subdirectory(${SRC_TOP_DIR}/common/utils        ${CMAKE_CURRENT_BINARY_DIR}/utils)
add_subdirectory(${SRC_TOP_DIR}/udp                 ${CMAKE_CURRENT_BINARY_DIR}/udp)
add_subdirectory(${SRC_TOP_DIR}/pfcp                ${CMAKE_CURRENT_BINARY_DIR}/pfcp)
add_subdirectory(${SRC_TOP_DIR}/gtpv1u              ${CMAKE_CURRENT_BINARY_DIR}/gtpv1u)
add_subdirectory(${SRC_TOP_DIR}/upf_app             ${CMAKE_CURRENT_BINARY_DIR}/upf_app)
add_subdirectory(${SRC_TOP_DIR}/upf_app/app         ${CMAKE_CURRENT_BINARY_DIR}/app)
add_subdirectory(${SRC_TOP_DIR}/upf_app/simpleswitch ${CMAKE_CURRENT_BINARY_DIR}/simpleswitch)

# -----------------------------------------------------------------------------
# Version stamp
# -----------------------------------------------------------------------------
set(GIT_BRANCH "UNKNOWN")
set(GIT_COMMIT_HASH "UNKNOWN")
set(GIT_COMMIT_DATE "UNKNOWN")

find_package(Git QUIET)
if(GIT_FOUND)
  foreach(pair "GIT_BRANCH;rev-parse;--abbrev-ref;HEAD"
               "GIT_COMMIT_HASH;log;-1;--format=%h"
               "GIT_COMMIT_DATE;log;-1;--format=%cd")
    list(POP_FRONT pair _var)
    execute_process(COMMAND ${GIT_EXECUTABLE} ${pair}
      WORKING_DIRECTORY ${OPENAIRCN_DIR}
      OUTPUT_VARIABLE   _out
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_QUIET)
    if(_out)
      set(${_var} "${_out}")
    endif()
  endforeach()
endif()

string(TIMESTAMP BUILD_DATE "%Y-%m-%d")
string(TIMESTAMP BUILD_TIME "%H:%M:%S")

# -----------------------------------------------------------------------------
# upf executable
# -----------------------------------------------------------------------------
add_executable(upf
  main.cpp
  options.cpp
  "${SRC_TOP_DIR}/itti/itti.cpp"
  "${SRC_TOP_DIR}/itti/itti_msg.cpp"
  "${UPF_APP_DIR}/utils/startup_banner.cpp")

# main.cpp includes <upf_xdp_user.h>, which pulls in xdp_n3_entry_skel.h and
# friends. This is already implied by linking the static UPF_XDP (which depends
# on upf_xdp_all), but stated explicitly so the requirement survives any future
# change to how these libraries are linked.
add_dependencies(upf upf_xdp_all)

# Emit the binary at the top of the build tree, i.e. build/upf/build/upf.
#
# The legacy top-level list file pulled src/oai_upf/CMakeLists.txt in with
# include(), so the `upf` target was created in build/upf's own scope and its
# executable landed directly in the binary root. This file is now brought in
# with add_subdirectory() (which is what makes CMAKE_CURRENT_SOURCE_DIR here
# mean src/oai_upf rather than build/upf), and that gives the directory its own
# binary subdirectory -- so without this the binary would appear at
# build/upf/build/oai_upf/upf instead.
#
# build/scripts/build_upf hardcodes the old location in three places: the
# `compilations upf upf $OPENAIRCN_DIR/build/upf/build/upf` success check
# (:234), the chmod (:238), and the install cp (:239). Moving the artifact
# makes the build report "upf compilation failed" after a completely successful
# compile, and silently skips the install.
set_target_properties(upf PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

target_include_directories(upf PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${SRC_TOP_DIR}/itti"
  "${UPF_APP_DIR}/utils"
  "${COMMON_SRC_DIR}/nas"
  "${COMMON_SRC_DIR}/nas/common"
  "${COMMON_SRC_DIR}/nas/utils")

# add_definitions() put every one of these on every target in the directory and
# below, including the BPF objects. As target properties they reach `upf` alone.
target_compile_definitions(upf PRIVATE
  CMAKER
  PACKAGE_NAME="UPF"
  PACKAGE_BUGREPORT="openaircn-user@lists.eurecom.fr"
  PACKAGE_VERSION="Branch: ${GIT_BRANCH} Abrev. Hash: ${GIT_COMMIT_HASH} Date: ${GIT_COMMIT_DATE}"
  BUILD_DATE="${BUILD_DATE}"
  BUILD_TIME="${BUILD_TIME}"
  BSTRLIB_CAN_USE_STL=1
  BSTRLIB_CAN_USE_IOSTREAM=1
  BSTRLIB_THROWS_EXCEPTIONS=1
  $<$<BOOL:${LOG_OAI}>:LOG_OAI=1>
  $<$<BOOL:${LOG_OAI_MINIMAL}>:LOG_OAI_MINIMAL=1>
  $<$<BOOL:${DISPLAY_LICENCE_INFO}>:DISPLAY_LICENCE_INFO=1>
  $<$<BOOL:${USE_LTTNG}>:LOGGER_CAN_USE_LTTNG>)

# -----------------------------------------------------------------------------
# common-src modules
#
# These are NOT find-modules: each one appends its own .cpp files to the target
# named by NF_TARGET via target_sources(), guarded by `if(TARGET ${NF_TARGET})`.
# So they MUST be included after add_executable(upf) -- included earlier the
# guard is false, they silently contribute nothing, and the link fails with
# undefined references such as
#   oai::logger::logger_registry::get_logger(std::string const&)
#
# They also call directory-scoped include_directories(), which is why the paths
# they add are not repeated in the target_include_directories() call above.
#
# Order matters: http.cmake itself includes logger.cmake and common.cmake, and
# common_model.cmake consumes USED_COMMON_MODEL_SRC_FILES, which the model
# modules populate. This is the legacy order, preserved deliberately.
# -----------------------------------------------------------------------------
include(${COMMON_SRC_DIR}/config/config.cmake)
include(${COMMON_SRC_DIR}/http/http.cmake)
include(${COMMON_SRC_DIR}/logger/logger.cmake)
include(${COMMON_SRC_DIR}/model/nrf_model.cmake)
include(${COMMON_SRC_DIR}/model/common_model.cmake)
include(${COMMON_SRC_DIR}/utils/utils.cmake)

# Host warning flags. The legacy CMAKE_C_FLAGS accumulated -Wall, -msse4.2,
# -std=gnu99, -fPIC, -fno-strict-aliasing and a long -DHAVE_* block over lines
# 134-139 -- and line 140 then did a plain set() that threw all of it away. Only
# the four -Wno-* suppressions on that last line ever reached the compiler.
target_compile_options(upf PRIVATE
  -Wall
  -Wno-unused-function
  -Wno-return-type
  -Wno-empty-body
  $<$<STREQUAL:${CMAKE_SYSTEM_PROCESSOR},x86_64>:-msse4.2>
  $<$<STREQUAL:${CMAKE_SYSTEM_PROCESSOR},armv7l>:-mfloat-abi=hard>
  $<$<STREQUAL:${CMAKE_SYSTEM_PROCESSOR},armv7l>:-mfpu=neon>)

# --start-group is needed: APP, SIMPLE_SWITCH and the datapath libraries have
# circular references between them. Fixing that is a source-level change and is
# out of scope here, so the group is kept and made explicit.
target_link_libraries(upf PRIVATE
  -Wl,--start-group
    APP
    CN_UTILS
    GTPV1U
    PFCP
    SIMPLE_SWITCH
    UDP
    UPF_TC
    UPF_XDP
  -Wl,--end-group
  libbpf::bpf
  PkgConfig::CONFIGXX
  Threads::Threads
  CURL::libcurl
  cpr::cpr
  fmt::fmt
  # header-only, NOT spdlog::spdlog -- see note below
  spdlog::spdlog_header_only
  yaml-cpp
  ${FOLLY_LIBRARY}
  ${GLOG_LIBRARY}
  ${GFLAGS_LIBRARY}
  ${DOUBLECONV_LIBRARY}
  ${EVENT_LIBRARY}
  ${BOOST_SYSTEM_LIBRARY}
  ${CMAKE_DL_LIBS}
  m
  rt)

# -----------------------------------------------------------------------------
# spdlog: header-only, deliberately.
#
# The legacy build passed the bare name `spdlog` to the linker and defined none
# of the SPDLOG_* macros, so every translation unit compiled spdlog inline --
# header-only mode -- while also linking the compiled library. Inconsistent, but
# that is the behaviour the sources were written against.
#
# spdlog::spdlog defines SPDLOG_COMPILED_LIB, which stops spdlog pulling in its
# details/os-inl.h. That header is the only reason <unistd.h> ever reached
# src/upf_app/utils/startup_banner.cpp, which calls sleep(5) at line 1168
# without including <unistd.h> itself. Switching to the compiled library
# therefore breaks that file with "'sleep' was not declared in this scope".
#
# spdlog::spdlog_header_only reproduces the legacy behaviour exactly, so this
# CMake change stays behaviour-preserving.
#
# Follow-up, as a source change: add <unistd.h> to startup_banner.cpp (and audit
# for the same pattern elsewhere), then switch to spdlog::spdlog to stop
# recompiling spdlog in every translation unit.
# -----------------------------------------------------------------------------

if(USE_LTTNG)
  message(STATUS "LTTng tracing enabled")
  target_link_libraries(upf PRIVATE lttng-ust)
endif()

# Address sanitizer, previously spelled as a bare `${ASAN}` entry in the link
# line and set from three different places (Debug build type, the
# SANITIZE_OPTIONS environment variable, and the STATIC_LINKING branch -- which
# enabled it precisely where it cannot work).
option(ENABLE_ASAN "Build with AddressSanitizer" OFF)
if(ENABLE_ASAN AND NOT STATIC_LINKING)
  target_compile_options(upf PRIVATE -fsanitize=address -fno-omit-frame-pointer)
  target_link_options(upf    PRIVATE -fsanitize=address)
elseif(ENABLE_ASAN AND STATIC_LINKING)
  message(WARNING "ENABLE_ASAN ignored: ASan does not support -static.")
endif()

if(STATIC_LINKING)
  # Legacy read: SET_TARGET_PROPERTIES(spgwc PROPERTIES LINK_SEARCH_END_STATIC 1)
  # `spgwc` is the SPGW-C binary -- no such target exists in this project, so
  # configuring with STATIC_LINKING=ON failed outright. The target is `upf`.
  set_target_properties(upf PROPERTIES LINK_SEARCH_END_STATIC 1)
  target_link_options(upf PRIVATE -static)
endif()

include(GNUInstallDirs)
install(TARGETS upf RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
