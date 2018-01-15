set(RETDEC_TESTS_CONFIG_SOURCES
	base_tests.cpp
	classes_tests.cpp
	documentation_tests.cpp
	file_format_tests.cpp
	functions_tests.cpp
	objects_tests.cpp
	tool_info_tests.cpp
	vtables_tests.cpp
	architecture_tests.cpp
	calling_convention_tests.cpp
	config_tests.cpp
	file_type_tests.cpp
	language_tests.cpp
	patterns_tests.cpp
	types_tests.cpp
)

add_executable(retdec-tests-config ${RETDEC_TESTS_CONFIG_SOURCES})
target_link_libraries(retdec-tests-config retdec-config gmock_main)
install(TARGETS retdec-tests-config RUNTIME DESTINATION ${RETDEC_TESTS_DIR})
