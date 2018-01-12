set(RETDEC_TESTS_LLVMIR_EMUL_SOURCES
	llvmir_emul_tests.cpp
)

add_executable(retdec-tests-llvm-emul ${RETDEC_TESTS_LLVMIR_EMUL_SOURCES})
target_link_libraries(retdec-tests-llvm-emul retdec-utils retdec-llvmir-emul gmock_main)
target_include_directories(retdec-tests-llvm-emul PUBLIC ${PROJECT_SOURCE_DIR}/tests/)
install(TARGETS retdec-tests-llvm-emul RUNTIME DESTINATION ${RETDEC_TESTS_DIR})
