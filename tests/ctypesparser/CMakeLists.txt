set(RETDEC_TESTS_CTYPESPARSER_SOURCES
	json_ctypes_parser_tests.cpp
	borland_ast_to_ctypes_tests.cpp
	ms_ast_to_ctypes_tests.cpp
	itanium_ast_to_ctypes_tests.cpp
)

add_executable(retdec-tests-ctypesparser ${RETDEC_TESTS_CTYPESPARSER_SOURCES})
target_link_libraries(retdec-tests-ctypesparser retdec-ctypesparser gmock_main)
install(TARGETS retdec-tests-ctypesparser RUNTIME DESTINATION ${RETDEC_TESTS_DIR})
