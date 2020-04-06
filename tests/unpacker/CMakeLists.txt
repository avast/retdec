
add_executable(tests-unpacker
	dynamic_buffer_tests.cpp
	signature_tests.cpp
)

target_link_libraries(tests-unpacker
	retdec::unpacker
	retdec::deps::gmock_main
)

set_target_properties(tests-unpacker
	PROPERTIES
		OUTPUT_NAME "retdec-tests-unpacker"
)

install(TARGETS tests-unpacker
	RUNTIME DESTINATION ${RETDEC_INSTALL_TESTS_DIR}
)
