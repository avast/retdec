
set(UNPACKER_TESTS_SOURCES
	dynamic_buffer_tests.cpp
	signature_tests.cpp
)

if(NOT TARGET unpacker-tests)

	add_executable(unpacker-tests ${UNPACKER_TESTS_SOURCES})
	target_link_libraries(unpacker-tests unpacker gmock_main)
	install(TARGETS unpacker-tests RUNTIME DESTINATION bin/unit-tests)

endif()
