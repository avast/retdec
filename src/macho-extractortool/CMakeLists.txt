
add_executable(macho-extractortool
	macho_extractor.cpp
)

target_link_libraries(macho-extractortool
	retdec::macho-extractor
	retdec::utils
	retdec::rapidjson
)

set_target_properties(macho-extractortool
	PROPERTIES
		OUTPUT_NAME "retdec-macho-extractor"
)

install(TARGETS macho-extractortool
	RUNTIME DESTINATION bin
)
