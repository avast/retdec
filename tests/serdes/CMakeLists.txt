
add_executable(retdec-tests-serdes
	calling_convention_tests.cpp
	class_tests.cpp
	pattern_tests.cpp
)
target_link_libraries(retdec-tests-serdes
	retdec-serdes
	gmock_main
)
install(TARGETS retdec-tests-serdes RUNTIME DESTINATION ${RETDEC_TESTS_DIR})
