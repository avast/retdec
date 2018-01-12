set(DEMANGLER_GRAMMAR_GEN_SOURCES
	demangler_grammar_gen.cpp
)

add_executable(retdec-demangler-grammar-gen ${DEMANGLER_GRAMMAR_GEN_SOURCES})
target_link_libraries(retdec-demangler-grammar-gen retdec-demangler)
install(TARGETS retdec-demangler-grammar-gen RUNTIME DESTINATION bin)
