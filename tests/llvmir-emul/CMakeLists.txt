
set(LLVMIR_EMUL_TESTS_SOURCES
	llvmir_emul_tests.cpp
)

add_executable(llvm-emul-tests ${LLVMIR_EMUL_TESTS_SOURCES})
target_link_libraries(llvm-emul-tests tl-cpputils llvmir-emul gmock_main)
target_include_directories(llvm-emul-tests PUBLIC ${PROJECT_SOURCE_DIR}/tests/)
install(TARGETS llvm-emul-tests RUNTIME DESTINATION bin/unit-tests)
