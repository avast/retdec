
add_executable(retdec-tests-config
	config_tests.cpp
)
target_link_libraries(retdec-tests-config
	retdec-common
	retdec-config
	gmock_main
)
install(TARGETS retdec-tests-config RUNTIME DESTINATION ${RETDEC_TESTS_DIR})
