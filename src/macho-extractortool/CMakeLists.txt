
set(MACHO_EXTRACTOR_SOURCES
	macho_extractor.cpp
)

if(NOT TARGET macho-extractortool)

	add_executable(macho-extractortool ${MACHO_EXTRACTOR_SOURCES})
	set_target_properties(macho-extractortool PROPERTIES OUTPUT_NAME "macho-extractor")
	target_link_libraries(macho-extractortool macho-extractor tl-cpputils rapidjson)
	install(TARGETS macho-extractortool RUNTIME DESTINATION bin)

endif()
