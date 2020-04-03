
add_executable(tests-common
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

target_link_libraries(tests-common
	retdec::common
	retdec::deps::gmock_main
)

set_target_properties(tests-common
	PROPERTIES
		OUTPUT_NAME "retdec-tests-common"
)

install(TARGETS tests-common
	RUNTIME DESTINATION ${RETDEC_INSTALL_TESTS_DIR}
)
