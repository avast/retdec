set(DEMANGLER_LLVM_SOURCES
		ItaniumDemangle.cpp
		MicrosoftDemangle.cpp
		MicrosoftDemangleNodes.cpp
		demangler_base.cpp
		demangler_factory.cpp
		itanium_demangler_adapter.cpp
		microsoft_demangler_adapter.cpp
		borland_demangler.cpp
		borland_ast.cpp
		borland_ast_parser.cpp
		context.cpp
		borland_ast_types.cpp
		Demangle.cpp
		)

add_library(llvm-demangler STATIC ${DEMANGLER_LLVM_SOURCES})
target_link_libraries(llvm-demangler retdec-ctypesparser)
target_include_directories(llvm-demangler PUBLIC ${PROJECT_SOURCE_DIR}/include/)