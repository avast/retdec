
set(CTYPESPARSER_TESTS_SOURCES
	json_ctypes_parser_tests.cpp
)

add_executable(ctypesparser-tests ${CTYPESPARSER_TESTS_SOURCES})
target_link_libraries(ctypesparser-tests ctypesparser gmock_main)
install(TARGETS ctypesparser-tests RUNTIME DESTINATION bin/unit-tests)
