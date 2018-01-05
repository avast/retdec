
set(TL_CPPUTILS_TESTS_SOURCES
	address_tests.cpp
	alignment_tests.cpp
	array_tests.cpp
	byte_value_storage_tests.cpp
	const_tests.cpp
	container_tests.cpp
	conversion_tests.cpp
	filter_iterator_tests.cpp
	math_tests.cpp
	range_tests.cpp
	scope_exit_tests.cpp
	string_tests.cpp
	time_tests.cpp
	value_tests.cpp
)

if(NOT TARGET tl-cpputils-tests)

	add_executable(tl-cpputils-tests ${TL_CPPUTILS_TESTS_SOURCES})
	target_link_libraries(tl-cpputils-tests tl-cpputils gmock_main)
	install(TARGETS tl-cpputils-tests RUNTIME DESTINATION bin/unit-tests)

endif()
