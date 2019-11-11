
add_executable(retdec-tests-config
	base_tests.cpp
	classes_tests.cpp
	documentation_tests.cpp
	functions_tests.cpp
	objects_tests.cpp
	tool_info_tests.cpp
	config_tests.cpp
	patterns_tests.cpp
	types_tests.cpp
)
target_link_libraries(retdec-tests-config
	retdec-common
	retdec-config
	gmock_main
)
install(TARGETS retdec-tests-config RUNTIME DESTINATION ${RETDEC_TESTS_DIR})
