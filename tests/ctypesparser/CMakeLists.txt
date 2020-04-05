
add_executable(tests-ctypesparser
	json_ctypes_parser_tests.cpp
)

target_link_libraries(tests-ctypesparser
	retdec::ctypesparser
	retdec::deps::gmock_main
)

set_target_properties(tests-ctypesparser
	PROPERTIES
		OUTPUT_NAME "retdec-tests-ctypesparser"
)

install(TARGETS tests-ctypesparser
	RUNTIME DESTINATION ${RETDEC_INSTALL_TESTS_DIR}
)
