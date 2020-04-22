
add_executable(tests-fileformat
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

target_include_directories(tests-fileformat
	PRIVATE
		${RETDEC_TESTS_DIR}
)

target_link_libraries(tests-fileformat
	retdec::fileformat
	retdec::utils
	retdec::deps::gmock_main
)

set_target_properties(tests-fileformat
	PROPERTIES
		OUTPUT_NAME "retdec-tests-fileformat"
)

install(TARGETS tests-fileformat
	RUNTIME DESTINATION ${RETDEC_INSTALL_TESTS_DIR}
)
