
set(CTYPES_TESTS_SOURCES
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

add_executable(ctypes-tests ${CTYPES_TESTS_SOURCES})
target_link_libraries(ctypes-tests ctypes gmock_main)
install(TARGETS ctypes-tests RUNTIME DESTINATION bin/unit-tests)
