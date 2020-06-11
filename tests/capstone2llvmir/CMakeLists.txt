
add_executable(tests-capstone2llvmir
	arm_tests.cpp
	arm64_tests.cpp
	mips_tests.cpp
	powerpc_tests.cpp
	x86_tests.cpp
)

target_include_directories(tests-capstone2llvmir
	PRIVATE
		${RETDEC_TESTS_DIR}
)

target_link_libraries(tests-capstone2llvmir
	retdec::capstone2llvmir
	retdec::llvmir-emul
	retdec::utils
	retdec::deps::keystone
	retdec::deps::gmock_main
)

if(MSVC)
	target_compile_options(tests-capstone2llvmir PUBLIC "/bigobj")
endif()

set_target_properties(tests-capstone2llvmir
	PROPERTIES
		OUTPUT_NAME "retdec-tests-capstone2llvmir"
)

install(TARGETS tests-capstone2llvmir
	RUNTIME DESTINATION ${RETDEC_INSTALL_TESTS_DIR}
)
