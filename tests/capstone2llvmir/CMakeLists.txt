
set(CAPSTONE2LLVMIR_TESTS_SOURCES
	arm_tests.cpp
	mips_tests.cpp
	powerpc_tests.cpp
	x86_tests.cpp
)

add_executable(capstone2llvmir-tests ${CAPSTONE2LLVMIR_TESTS_SOURCES})
target_link_libraries(capstone2llvmir-tests capstone2llvmir llvmir-emul keystone gmock_main)
target_include_directories(capstone2llvmir-tests PUBLIC ${PROJECT_SOURCE_DIR}/tests/)
install(TARGETS capstone2llvmir-tests RUNTIME DESTINATION bin/unit-tests)
