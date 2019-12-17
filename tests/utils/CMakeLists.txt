
add_executable(retdec-tests-utils
	alignment_tests.cpp
	array_tests.cpp
	binary_path_tests.cpp
	byte_value_storage_tests.cpp
	const_tests.cpp
	container_tests.cpp
	conversion_tests.cpp
	filter_iterator_tests.cpp
	math_tests.cpp
	memory_tests.cpp
	scope_exit_tests.cpp
	string_tests.cpp
	time_tests.cpp
)
target_link_libraries(retdec-tests-utils
	retdec-utils
	gmock_main
)
install(TARGETS retdec-tests-utils RUNTIME DESTINATION ${RETDEC_TESTS_DIR})
