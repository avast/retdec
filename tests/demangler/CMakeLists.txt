
set(DEMANGLER_TESTS_SOURCES
	borland_tests.cpp
	gcc_tests.cpp
	msvc_tests.cpp
)

if(NOT TARGET demangler-tests)

	add_executable(demangler-tests ${DEMANGLER_TESTS_SOURCES})
	target_link_libraries(demangler-tests demangler gmock_main)
	install(TARGETS demangler-tests RUNTIME DESTINATION bin/unit-tests)

endif()
