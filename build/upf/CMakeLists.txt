# SPDX-License-Identifier: LicenseRef-CSSL-1.0

cmake_minimum_required (VERSION 3.0.2)
project(OpenAirInterface)
set (  PACKAGE_NAME                    "UPF" )
set (  STATIC_LINKING                   False )
#############################################
# Base directories, compatible with legacy OAI building
################################################
set (OPENAIRCN_DIR   $ENV{OPENAIRCN_DIR})
set (BUILD_TOP_DIR   ${OPENAIRCN_DIR}/build)
set (SRC_TOP_DIR     $ENV{OPENAIRCN_DIR}/src)

################################################
# For common-src usage
################################################
set (  NF_TARGET                        upf )
set (  MOUNTED_COMMON                   common-src)

include(${CMAKE_CURRENT_SOURCE_DIR}/../../src/oai_upf/CMakeLists.txt)

#ADD_SUBDIRECTORY(${CMAKE_CURRENT_SOURCE_DIR}/../../src/upf ${CMAKE_CURRENT_BINARY_DIR}/upf)
