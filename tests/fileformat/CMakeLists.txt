set(RETDEC_TESTS_FILEFORMAT_SOURCES
	coff_format_tests.cpp
	elf_format_tests.cpp
	format_detection_tests.cpp
	format_factory_tests.cpp
	intel_hex_format_20bit_tests.cpp
	intel_hex_format_tests.cpp
	intel_hex_token_test.cpp
	macho_format_tests.cpp
	pe_format_tests.cpp
	raw_data_format_tests.cpp
)

add_executable(retdec-tests-fileformat ${RETDEC_TESTS_FILEFORMAT_SOURCES})
target_link_libraries(retdec-tests-fileformat retdec-fileformat retdec-utils gmock_main)
target_include_directories(retdec-tests-fileformat PUBLIC ${PROJECT_SOURCE_DIR}/tests/)
install(TARGETS retdec-tests-fileformat RUNTIME DESTINATION ${RETDEC_TESTS_DIR})
