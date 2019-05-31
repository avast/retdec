
set(DEMANGLER_LLVM_SOURCES
	demangler_base.cpp
	itanium_demangler_adapter.cpp
	microsoft_demangler_adapter.cpp
	borland_demangler.cpp
	borland_ast_parser.cpp
	context.cpp
	borland_ast/array_type.cpp
	borland_ast/built_in_type.cpp
	borland_ast/char_type.cpp
	borland_ast/conversion_operator.cpp
	borland_ast/float_type.cpp
	borland_ast/function_node.cpp
	borland_ast/function_type.cpp
	borland_ast/integral_type.cpp
	borland_ast/name_node.cpp
	borland_ast/named_type.cpp
	borland_ast/node.cpp
	borland_ast/node_array.cpp
	borland_ast/pointer_type.cpp
	borland_ast/parentheses_node.cpp
	borland_ast/reference_type.cpp
	borland_ast/rreference_type.cpp
	borland_ast/qualifiers.cpp
	borland_ast/template_node.cpp
	borland_ast/type_node.cpp
)

add_library(retdec-demangler STATIC ${DEMANGLER_LLVM_SOURCES})
target_link_libraries(retdec-demangler retdec-ctypesparser llvm)
target_include_directories(retdec-demangler PUBLIC ${PROJECT_SOURCE_DIR}/include/)