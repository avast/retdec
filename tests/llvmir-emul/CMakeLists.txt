
add_executable(tests-llvm-emul
	llvmir_emul_tests.cpp
)

target_include_directories(tests-llvm-emul
	PRIVATE
		${RETDEC_TESTS_DIR}
)

target_link_libraries(tests-llvm-emul
	retdec::utils
	retdec::llvmir-emul
	retdec::deps::gmock_main
)

set_target_properties(tests-llvm-emul
	PROPERTIES
		OUTPUT_NAME "retdec-tests-llvm-emul"
)

install(TARGETS tests-llvm-emul
	RUNTIME DESTINATION ${RETDEC_INSTALL_TESTS_DIR}
)
