
set(FILEFORMAT_TESTS_SOURCES
	elf_format_tests.cpp
	intel_hex_format_20bit_tests.cpp
	intel_hex_format_tests.cpp
	intel_hex_token_test.cpp
	raw_data_format_tests.cpp
)

if(NOT TARGET fileformat-tests)

	add_executable(fileformat-tests ${FILEFORMAT_TESTS_SOURCES})
	target_link_libraries(fileformat-tests fileformat tl-cpputils gmock_main)
	install(TARGETS fileformat-tests RUNTIME DESTINATION bin/unit-tests)

endif()
