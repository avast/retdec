set(RETDEC_TESTS_LOADER_SOURCES
	name_generator_tests.cpp
	overlap_resolver_tests.cpp
	segment_data_source_tests.cpp
	segment_tests.cpp
)

add_executable(retdec-tests-loader ${RETDEC_TESTS_LOADER_SOURCES})
target_link_libraries(retdec-tests-loader retdec-loader retdec-utils gmock_main)
install(TARGETS retdec-tests-loader RUNTIME DESTINATION ${RETDEC_TESTS_DIR})
