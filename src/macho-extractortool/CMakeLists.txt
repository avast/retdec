set(MACHO_EXTRACTOR_SOURCES
	macho_extractor.cpp
)

add_executable(retdec-macho-extractortool ${MACHO_EXTRACTOR_SOURCES})
set_target_properties(retdec-macho-extractortool PROPERTIES OUTPUT_NAME "retdec-macho-extractor")
target_link_libraries(retdec-macho-extractortool retdec-macho-extractor retdec-utils rapidjson)
install(TARGETS retdec-macho-extractortool RUNTIME DESTINATION bin)
