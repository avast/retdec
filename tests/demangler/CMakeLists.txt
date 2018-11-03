set(RETDEC_TESTS_DEMANGLER_SOURCES
	borland_tests.cpp
	gcc_tests.cpp
	msvc_tests.cpp
	llvm_itanium_demangler_tests.cpp
	llvm_microsoft_demangler_tests.cpp
	borland_demangler_tests.cpp
)

add_executable(retdec-tests-demangler ${RETDEC_TESTS_DEMANGLER_SOURCES})
target_link_libraries(retdec-tests-demangler llvm-demangler retdec-demangler gmock_main)
install(TARGETS retdec-tests-demangler RUNTIME DESTINATION ${RETDEC_TESTS_DIR})
