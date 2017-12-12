
set(LLVM_SUPPORT_TESTS_SOURCES
	utils_tests.cpp
)

add_executable(llvm-support-tests ${LLVM_SUPPORT_TESTS_SOURCES})
target_link_libraries(llvm-support-tests llvm-support gmock_main)
install(TARGETS llvm-support-tests RUNTIME DESTINATION bin/unit-tests)
