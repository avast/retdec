set(RETDEC_TESTS_LLVM_SUPPORT_SOURCES
	utils_tests.cpp
)

add_executable(retdec-tests-llvm-support ${RETDEC_TESTS_LLVM_SUPPORT_SOURCES})
target_link_libraries(retdec-tests-llvm-support retdec-llvm-support gmock_main)
install(TARGETS retdec-tests-llvm-support RUNTIME DESTINATION ${RETDEC_TESTS_DIR})
