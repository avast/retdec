
add_executable(tests-config
	config_tests.cpp
)

target_link_libraries(tests-config
	retdec::common
	retdec::config
	retdec::deps::gmock_main
)

set_target_properties(tests-config
	PROPERTIES
		OUTPUT_NAME "retdec-tests-config"
)

install(TARGETS tests-config
	RUNTIME DESTINATION ${RETDEC_INSTALL_TESTS_DIR}
)
