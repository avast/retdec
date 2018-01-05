
set(DEMANGLERTOOL_SOURCES
	demangler.cpp
)

add_executable(demanglertool ${DEMANGLERTOOL_SOURCES})
set_target_properties(demanglertool PROPERTIES OUTPUT_NAME "demangler")
target_link_libraries(demanglertool demangler)
install(TARGETS demanglertool RUNTIME DESTINATION bin)
