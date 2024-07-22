include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger)

add_executable(
                UPFTest
        framed_routing/LocalRoutingTest.cpp
        framed_routing/FramedRoutingTest.cpp
)
        target_link_libraries(UPFTest PUBLIC FRAMED_ROUTING SIMPLE_SWITCH GTest::gtest_main fmt)
        include(GoogleTest)
        gtest_discover_tests(UPFTest)

