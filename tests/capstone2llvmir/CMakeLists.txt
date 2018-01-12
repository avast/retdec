set(RETDEC_TESTS_CAPSTONE2LLVMIR_SOURCES
	arm_tests.cpp
	mips_tests.cpp
	powerpc_tests.cpp
	x86_tests.cpp
)

add_executable(retdec-tests-capstone2llvmir ${RETDEC_TESTS_CAPSTONE2LLVMIR_SOURCES})
target_link_libraries(retdec-tests-capstone2llvmir retdec-capstone2llvmir retdec-llvmir-emul keystone gmock_main)
target_include_directories(retdec-tests-capstone2llvmir PUBLIC ${PROJECT_SOURCE_DIR}/tests/)
install(TARGETS retdec-tests-capstone2llvmir RUNTIME DESTINATION ${RETDEC_TESTS_DIR})
