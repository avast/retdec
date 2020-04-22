
add_executable(tests-loader
	name_generator_tests.cpp
	overlap_resolver_tests.cpp
	segment_data_source_tests.cpp
	segment_tests.cpp
)

target_link_libraries(tests-loader
	retdec::common
	retdec::loader
	retdec::utils
	retdec::deps::gmock_main
)

set_target_properties(tests-loader
	PROPERTIES
		OUTPUT_NAME "retdec-tests-loader"
)

install(TARGETS tests-loader
	RUNTIME DESTINATION ${RETDEC_INSTALL_TESTS_DIR}
)
