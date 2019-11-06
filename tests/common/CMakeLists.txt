
add_executable(retdec-tests-common
	address_tests.cpp
	range_tests.cpp
)
target_link_libraries(retdec-tests-common
	retdec-common
	gmock_main
)
install(TARGETS retdec-tests-common RUNTIME DESTINATION ${RETDEC_TESTS_DIR})
