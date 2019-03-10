add_subdirectory(demangler_llvm)

set(DEMANGLER_LLVM_SOURCES
	demangler_base.cpp
	demangler_factory.cpp
	itanium_demangler_adapter.cpp
	microsoft_demangler_adapter.cpp
	borland_demangler.cpp
	borland_ast.cpp
	borland_ast_parser.cpp
	context.cpp
	borland_ast_types.cpp
	)

add_library(retdec-demangler STATIC ${DEMANGLER_LLVM_SOURCES})
target_link_libraries(retdec-demangler llvm-demangler retdec-ctypesparser)
target_include_directories(retdec-demangler PUBLIC ${PROJECT_SOURCE_DIR}/include/)