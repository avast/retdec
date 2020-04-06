
add_executable(tests-ctypes
	annotation_in_tests.cpp
	annotation_inout_tests.cpp
	annotation_optional_tests.cpp
	annotation_out_tests.cpp
	array_type_tests.cpp
	call_convention_tests.cpp
	composite_type_tests.cpp
	context_tests.cpp
	enum_type_tests.cpp
	floating_point_type_tests.cpp
	function_declaration_tests.cpp
	function_tests.cpp
	function_type_tests.cpp
	header_file_tests.cpp
	integral_type_tests.cpp
	member_tests.cpp
	module_tests.cpp
	parameter_tests.cpp
	pointer_type.cpp
	struct_type_tests.cpp
	typedefed_type_tests.cpp
	union_type_tests.cpp
	unknown_type_tests.cpp
	visit_all_visitor_tests.cpp
	void_type_tests.cpp
)

target_link_libraries(tests-ctypes
	retdec::ctypes
	retdec::deps::gmock_main
)

set_target_properties(tests-ctypes
	PROPERTIES
		OUTPUT_NAME "retdec-tests-ctypes"
)

install(TARGETS tests-ctypes
	RUNTIME DESTINATION ${RETDEC_INSTALL_TESTS_DIR}
)
