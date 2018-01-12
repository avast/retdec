set(RETDEC_TESTS_FILEFORMAT_SOURCES
	elf_format_tests.cpp
	intel_hex_format_20bit_tests.cpp
	intel_hex_format_tests.cpp
	intel_hex_token_test.cpp
	raw_data_format_tests.cpp
)

add_executable(retdec-tests-fileformat ${RETDEC_TESTS_FILEFORMAT_SOURCES})
target_link_libraries(retdec-tests-fileformat retdec-fileformat retdec-utils gmock_main)
install(TARGETS retdec-tests-fileformat RUNTIME DESTINATION ${RETDEC_TESTS_DIR})
