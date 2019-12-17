
add_executable(retdec-tests-common
	address_tests.cpp
	architecture_tests.cpp
	class_tests.cpp
	file_format_tests.cpp
	file_type_tests.cpp
	function_tests.cpp
	language_tests.cpp
	object_tests.cpp
	patterns_tests.cpp
	range_tests.cpp
	tool_info_tests.cpp
	type_tests.cpp
)
target_link_libraries(retdec-tests-common
	retdec-common
	gmock_main
)
install(TARGETS retdec-tests-common RUNTIME DESTINATION ${RETDEC_TESTS_DIR})
