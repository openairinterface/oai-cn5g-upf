#include_directories(${CMAKE_SOURCE_DIR}/)
include_directories(${SRC_TOP_DIR}/upf_app)
include_directories(${SRC_TOP_DIR}/upf_app/utils)
include_directories(${SRC_TOP_DIR}/upf_app/include)
include_directories(${SRC_TOP_DIR}/upf_app/bpf)
include_directories(${SRC_TOP_DIR}/upf_app/simpleswitch)
include_directories(${SRC_TOP_DIR}/upf_app/interfaces)
include_directories(${SRC_TOP_DIR}/pfcp)
include_directories(${SRC_TOP_DIR}/common)
include_directories(${SRC_TOP_DIR}/common/utils)

include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger)

add_library(interfaces STATIC
  # ${CMAKE_CURRENT_SOURCE_DIR}/ForwardingActionRulesImpl.cpp
  # ${CMAKE_CURRENT_SOURCE_DIR}/PacketDetectionRulesImpl.cpp
  # ${CMAKE_CURRENT_SOURCE_DIR}/RulesUtilitiesImpl.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/SessionBpfImpl.cpp
)

# target_link_libraries(interfaces
#   # PRIVATE httplib::httplib
#   #PRIVATE nlohmann_json::nlohmann_json
#   #PRIVATE upf_xdp
#   #asan
#   PRIVATE spdlog
#   #upfutils
#   #oai
# )
#
#install(
#  TARGETS interfaces
#  RUNTIME
#)
