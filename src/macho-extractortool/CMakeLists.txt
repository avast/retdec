
add_executable(macho-extractortool
	macho_extractor.cpp
)

target_compile_features(macho-extractortool PUBLIC cxx_std_17)

target_link_libraries(macho-extractortool
	retdec::macho-extractor
	retdec::utils
	retdec::deps::rapidjson
)

set_target_properties(macho-extractortool
	PROPERTIES
		OUTPUT_NAME "retdec-macho-extractor"
)

install(TARGETS macho-extractortool
	RUNTIME DESTINATION ${RETDEC_INSTALL_BIN_DIR}
)
