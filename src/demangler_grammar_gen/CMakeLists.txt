
set(DEMANGLER_GRAMMAR_GEN_SOURCES
	demangler_grammar_gen.cpp
)

add_executable(demangler-grammar-gen ${DEMANGLER_GRAMMAR_GEN_SOURCES})
target_link_libraries(demangler-grammar-gen demangler)
install(TARGETS demangler-grammar-gen RUNTIME DESTINATION bin)
