
add_executable(tests-demangler
	borland_ast_to_ctypes_tests.cpp
	borland_context_tests.cpp
	borland_tests.cpp
	gcc_tests.cpp
	itanium_ast_to_ctypes_tests.cpp
	ms_ast_to_ctypes_tests.cpp
	msvc_tests.cpp
)

target_link_libraries(tests-demangler
	retdec::demangler
	retdec::deps::gmock_main
)

set_target_properties(tests-demangler
	PROPERTIES
		OUTPUT_NAME "retdec-tests-demangler"
)

install(TARGETS tests-demangler
	RUNTIME DESTINATION ${RETDEC_INSTALL_TESTS_DIR}
)
