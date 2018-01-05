
set(RETDEC_CONFIG_TESTS_SOURCES
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

if(NOT TARGET retdec-config-tests)

	add_executable(retdec-config-tests ${RETDEC_CONFIG_TESTS_SOURCES})
	target_link_libraries(retdec-config-tests retdec-config gmock_main)
	install(TARGETS retdec-config-tests RUNTIME DESTINATION bin/unit-tests)

endif()
