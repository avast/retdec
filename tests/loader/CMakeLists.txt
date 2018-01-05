
set(LOADER_TESTS_SOURCES
	name_generator_tests.cpp
	overlap_resolver_tests.cpp
	segment_data_source_tests.cpp
	segment_tests.cpp
)

if(NOT TARGET loader-tests)

	add_executable(loader-tests ${LOADER_TESTS_SOURCES})
	target_link_libraries(loader-tests loader tl-cpputils gmock_main)
	install(TARGETS loader-tests RUNTIME DESTINATION bin/unit-tests)

endif()
