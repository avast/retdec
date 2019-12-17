
add_executable(retdec-tests-loader
	name_generator_tests.cpp
	overlap_resolver_tests.cpp
	segment_data_source_tests.cpp
	segment_tests.cpp
)
target_link_libraries(
	retdec-tests-loader
	retdec-common
	retdec-loader
	retdec-utils
	gmock_main
)
install(TARGETS retdec-tests-loader RUNTIME DESTINATION ${RETDEC_TESTS_DIR})
