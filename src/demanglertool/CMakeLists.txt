set(DEMANGLERTOOL_SOURCES
	demangler.cpp
)

add_executable(retdec-demanglertool ${DEMANGLERTOOL_SOURCES})
set_target_properties(retdec-demanglertool PROPERTIES OUTPUT_NAME "retdec-demangler")
target_link_libraries(retdec-demanglertool retdec-demangler)
install(TARGETS retdec-demanglertool RUNTIME DESTINATION bin)
