# SPDX-License-Identifier: LicenseRef-CSSL-1.0
#
# CN_UTILS -- shared async shell-command helper.

add_library(CN_UTILS STATIC
  async_shell_cmd.cpp)

# PUBLIC: async_shell_cmd.hpp is included by consumers, so its directory is part
# of this target's interface rather than something each consumer re-declares.
target_include_directories(CN_UTILS PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}")

target_link_libraries(CN_UTILS PUBLIC upf::core oai::common)
