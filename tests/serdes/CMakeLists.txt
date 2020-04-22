
add_executable(tests-serdes
	calling_convention_tests.cpp
	class_tests.cpp
	pattern_tests.cpp
)

target_link_libraries(tests-serdes
	retdec::serdes
	retdec::deps::gmock_main
)

set_target_properties(tests-serdes
	PROPERTIES
		OUTPUT_NAME "retdec-tests-serdes"
)

install(TARGETS tests-serdes
	RUNTIME DESTINATION ${RETDEC_INSTALL_TESTS_DIR}
)
